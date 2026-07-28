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
    ///
    /// Cached, and resolved off the main actor. It used to call the keychain
    /// directly and is read from inside `UnlockForm.body`, so a blocking XPC to
    /// securityd ran on the main thread on every redraw — in the one process
    /// iOS kills outright for wedging its main thread. It answers `false` until
    /// the probe lands, which is the safe way round: the worst case is that the
    /// retry button appears a moment late.
    private(set) var canUseDeviceKey = false

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

    /// The keychain existence check, off the main actor.
    private static func probeDeviceKey() async -> Bool {
        await Task.detached(priority: .userInitiated) {
            VaultSession.hasStoredDeviceKey
        }.value
    }


    /// Try the device key straight away. Falls through to the password form when
    /// there is no key or the biometric is declined — never blocks on it.
    func start() async {
        // Probe here rather than trusting the cached value: this runs before the
        // first redraw, so nothing has populated it yet.
        let stored = await Self.probeDeviceKey()
        canUseDeviceKey = stored
        guard stored else { return }
        await open(fallback: "Couldn't unlock with Face ID.") {
            try await VaultSession.openWithDeviceKey(reason: "fill a password from Arca")
        }
    }

    func useDeviceKey() async {
        await open(fallback: "Couldn't unlock with Face ID.") {
            try await VaultSession.openWithDeviceKey(reason: "fill a password from Arca")
        }
    }

    /// Argon2id needs the vault header's memory cost in one block — 64 MiB at
    /// Arca's defaults — and an AutoFill extension has a hard memory ceiling it
    /// is KILLED for crossing, not slowed. `os_proc_available_memory` is
    /// Apple's documented way to ask whether an expensive operation will fit
    /// before starting it.
    ///
    /// The headroom is for everything the derivation does not account for: the
    /// decrypted vault, SwiftUI, and the allocator's own slack. Refusing with a
    /// sentence beats being terminated mid-fill, which the user sees as the
    /// keyboard simply forgetting Arca exists.
    private static let argon2Budget = 64 << 20
    private static let headroom = 24 << 20

    private static var canAffordPasswordUnlock: Bool {
        os_proc_available_memory() > argon2Budget + headroom
    }

    func unlock(password: String) async {
        guard Self.canAffordPasswordUnlock else {
            log.error("refusing password unlock: \(os_proc_available_memory(), privacy: .public) bytes available")
            failure = """
                Not enough memory here to derive the key. Open Arca and turn on \
                Face ID — filling then costs a fraction of this.
                """
            return
        }
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
