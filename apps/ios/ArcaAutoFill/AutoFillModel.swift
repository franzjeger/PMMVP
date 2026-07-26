// State for the AutoFill extension: unlock, then either fill the credential the
// OS named or show the ones matching the site.
//
// The extension is a SEPARATE PROCESS from the app, so it cannot borrow the
// app's unlocked session. It opens the vault itself: with the device key from
// the shared keychain when the user has turned quick unlock on — a biometric and
// a symmetric unwrap — and otherwise with the master password, which costs a
// full Argon2id derivation on every single fill. That difference is why
// `vault_ffi_enable_device_unlock` exists.

import AuthenticationServices
import Observation
import os

private let log = Logger(subsystem: "no.sybr.vault.ios.autofill", category: "provider")

@MainActor
@Observable
final class AutoFillModel {

    enum Phase: Equatable {
        case locked
        case unlocking
        case picking
    }

    /// The OS asked for one specific credential rather than a list.
    struct DirectRequest {
        let recordID: String
        let user: String
    }

    private(set) var phase: Phase = .locked
    private(set) var identities: [VaultIdentity] = []
    private(set) var failure: String?

    /// Whether the password field should offer a biometric retry.
    var canUseDeviceKey: Bool { VaultSession.hasStoredDeviceKey }

    private let domains: Set<String>
    private let direct: DirectRequest?
    private let onFill: @MainActor (ASPasswordCredential) -> Void
    private let onCancel: @MainActor () -> Void

    private var session: VaultSession?

    init(
        domains: Set<String>,
        direct: DirectRequest?,
        onFill: @escaping @MainActor (ASPasswordCredential) -> Void,
        onCancel: @escaping @MainActor () -> Void
    ) {
        self.domains = domains
        self.direct = direct
        self.onFill = onFill
        self.onCancel = onCancel
    }

    func cancel() { onCancel() }

    /// Try the device key straight away. Falls through to the password form when
    /// there is no key or the biometric is declined — never blocks on it.
    func start() async {
        guard canUseDeviceKey else { return }
        await open(fallback: "Couldn't unlock with Face ID.") {
            try await VaultSession.openWithDeviceKey(reason: "fill a password from Arca")
        }
    }

    func useDeviceKey() async {
        await open(fallback: "Couldn't unlock with Face ID.") {
            try await VaultSession.openWithDeviceKey(reason: "fill a password from Arca")
        }
    }

    func unlock(password: String) async {
        await open(fallback: "Couldn't unlock the vault.") {
            try await VaultSession.openWithMasterPassword(password)
        }
    }

    /// Both unlock paths converge here: get a handle, then either fill the one
    /// credential the OS named or show the ones matching the site.
    private func open(
        fallback: String,
        _ makeSession: @Sendable () async throws -> VaultSession
    ) async {
        guard phase != .unlocking else { return }
        phase = .unlocking
        failure = nil
        do {
            let session = try await makeSession()
            self.session = session

            // Asked for one credential: hand it back rather than showing a list
            // of one and making the user tap it.
            if let direct {
                await fill(recordID: direct.recordID, user: direct.user)
                return
            }

            identities = try await session.identities()
                .filter { domains.isEmpty || domains.contains($0.domain) }
                .sorted {
                    ($0.domain.lowercased(), $0.user.lowercased())
                        < ($1.domain.lowercased(), $1.user.lowercased())
                }
            phase = .picking
        } catch {
            log.error("unlock failed: \(vaultLogMessage(for: error), privacy: .public)")
            // A declined biometric is a choice, not an error: the password field
            // is already on screen.
            failure = Self.cancelled(error) ? nil : Self.message(error, fallback: fallback)
            phase = .locked
        }
    }

    func pick(_ identity: VaultIdentity) async {
        await fill(recordID: identity.id, user: identity.user)
    }

    private func fill(recordID: String, user: String) async {
        guard let session else { return }
        do {
            let password = try await session.password(forID: recordID)
            onFill(ASPasswordCredential(user: user, password: password))
        } catch {
            log.error("fill failed: \(vaultLogMessage(for: error), privacy: .public)")
            failure = Self.message(error, fallback: "Couldn't read that password.")
            // Back to the list if there is one, otherwise to the password field.
            phase = identities.isEmpty ? .locked : .picking
        }
    }

    private static func message(_ error: Error, fallback: String) -> String {
        (error as? LocalizedError)?.errorDescription ?? fallback
    }

    private static func cancelled(_ error: Error) -> Bool {
        guard let vaultError = error as? VaultError else { return false }
        switch vaultError {
        case .noDeviceKey(let status), .deviceKeyNotStored(let status):
            return status == errSecUserCanceled
        default:
            return false
        }
    }
}
