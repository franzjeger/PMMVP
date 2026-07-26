// The app's whole state: shut, opening, or open.
//
// There is no half-open state on purpose — a failed unlock leaves no handle
// behind, and `session` is the only thing that distinguishes locked from
// unlocked. Dropping it frees the Rust handle, which locks and zeroizes the
// vault, so `lock()` is one assignment rather than a teardown sequence.
//
// Nothing here caches a password. The store holds a handle and fetches one
// secret at a time through it, which is the point of the FFI's shape.

import Foundation
import Observation
import os

private let log = Logger(subsystem: "no.sybr.vault.ios", category: "store")

@MainActor
@Observable
final class VaultStore {

    enum Phase: Equatable {
        /// Nothing in the shared container to open — import one first.
        case needsVault
        case locked
        case unlocking
        case unlocked
    }

    private(set) var phase: Phase = .locked
    private(set) var identities: [VaultIdentity] = []
    /// The last failure, already phrased for a person.
    private(set) var failure: String?
    /// Whether AutoFill is switched on for Arca in Settings. `nil` until an
    /// unlock has actually asked, so the UI can stay quiet rather than guess.
    private(set) var autoFillEnabled: Bool?
    /// Whether the OPEN vault carries a device wrapping. Only meaningful while
    /// unlocked; `quickUnlockAvailable` is the question to ask before that.
    private(set) var quickUnlockEnabled = false
    var query = ""

    /// Whether a quick-unlock key is stored on this device. Cheap, and does not
    /// put a biometric prompt on screen just to decide which button to draw.
    var quickUnlockAvailable: Bool { VaultSession.hasStoredDeviceKey }

    /// Held only while unlocked.
    private var session: VaultSession?

    nonisolated init() {}

    /// Identities matching the current search, in a stable order.
    var results: [VaultIdentity] {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !needle.isEmpty else { return identities }
        return identities.filter {
            $0.user.lowercased().contains(needle)
                || $0.domain.lowercased().contains(needle)
                || $0.label.lowercased().contains(needle)
        }
    }

    /// Re-check whether there is a vault to open. Cheap; call it on appear.
    func refresh() {
        guard phase != .unlocked else { return }
        phase = VaultFile.exists ? .locked : .needsVault
    }

    func unlock(password: String) async {
        // Argon2id with the vault header's parameters — hundreds of
        // milliseconds, off the main actor inside VaultSession.
        await open(fallback: "Couldn't unlock the vault.") {
            try await VaultSession.openWithMasterPassword(password)
        }
    }

    /// Unlock with the stored device key, behind Face ID / Touch ID.
    func unlockWithDeviceKey() async {
        await open(fallback: "Couldn't unlock with Face ID.") {
            try await VaultSession.openWithDeviceKey(reason: "unlock your Arca vault")
        }
    }

    /// The two unlock paths differ only in how the handle is obtained.
    private func open(
        fallback: String,
        _ makeSession: @Sendable () async throws -> VaultSession
    ) async {
        guard phase != .unlocking else { return }
        phase = .unlocking
        failure = nil
        do {
            let session = try await makeSession()
            let identities = try await session.identities()
            self.session = session
            self.identities = identities.sorted {
                ($0.domain.lowercased(), $0.user.lowercased())
                    < ($1.domain.lowercased(), $1.user.lowercased())
            }
            quickUnlockEnabled = await session.hasDeviceUnlock()
            phase = .unlocked
            // After the phase flip on purpose: this is what puts Arca in the
            // QuickType bar, and it is metadata only, so nobody should be made
            // to wait behind it to see their own vault.
            autoFillEnabled = await CredentialIdentities.replace(with: self.identities)
        } catch {
            log.error("unlock failed: \(vaultLogMessage(for: error), privacy: .public)")
            failure = Self.cancelled(error) ? nil : Self.message(error, fallback: fallback)
            phase = VaultFile.exists ? .locked : .needsVault
        }
    }

    /// Turn quick unlock on for this device. Needs an open vault: the key wraps
    /// the vault key, which only exists while unlocked.
    func enableQuickUnlock() async {
        guard let session else { return }
        do {
            try await session.enableDeviceUnlock()
            quickUnlockEnabled = true
            failure = nil
        } catch {
            log.error("enable quick unlock failed: \(vaultLogMessage(for: error), privacy: .public)")
            failure = Self.cancelled(error) ? nil : Self.message(
                error, fallback: "Couldn't turn on quick unlock.")
        }
    }

    func disableQuickUnlock() async {
        guard let session else { return }
        do {
            try await session.disableDeviceUnlock()
            quickUnlockEnabled = false
            failure = nil
        } catch {
            log.error("disable quick unlock failed: \(vaultLogMessage(for: error), privacy: .public)")
            failure = Self.message(error, fallback: "Couldn't turn off quick unlock.")
        }
    }

    func lock() {
        // NOT clearing the credential identity store: it holds no secrets, and
        // it is what makes iOS offer Arca at all. The extension does its own
        // unlock when a suggestion is picked, so dropping the identities here
        // would make Arca invisible while protecting nothing.
        //
        // Frees the Rust handle on the vault queue, which re-seals and zeroizes.
        session = nil
        identities = []
        query = ""
        failure = nil
        phase = VaultFile.exists ? .locked : .needsVault
    }

    /// One password, fetched on demand and never stored here.
    func password(for identity: VaultIdentity) async -> String? {
        guard let session else { return nil }
        do {
            return try await session.password(forID: identity.id)
        } catch {
            log.error("password fetch failed: \(vaultLogMessage(for: error), privacy: .public)")
            failure = Self.message(error, fallback: "Couldn't read that password.")
            return nil
        }
    }

    /// Import a vault picked from Files. Takes the picker's `Result` whole so
    /// every way this can fail — picker included — lands in `failure`.
    ///
    /// Locks first: the handle open right now belongs to the file being replaced.
    func importVault(_ picked: Result<URL, Error>) {
        do {
            try VaultFile.replace(with: picked.get())
            // The stored device key was minted for the file just replaced, so it
            // opens nothing now. Left behind, the next launch would offer Face ID
            // and then fail.
            VaultSession.forgetDeviceKey()
            quickUnlockEnabled = false
            lock()
            // These describe the vault that was just replaced. The next unlock
            // publishes the new one's.
            Task { await CredentialIdentities.removeAll() }
            autoFillEnabled = nil
            failure = nil
        } catch {
            log.error("import failed: \(vaultLogMessage(for: error), privacy: .public)")
            failure = Self.message(error, fallback: "Couldn't import that file.")
        }
    }

    private static func message(_ error: Error, fallback: String) -> String {
        (error as? LocalizedError)?.errorDescription ?? fallback
    }

    /// A cancelled biometric prompt is a decision, not a fault. Reporting it as
    /// an error would put a red line under a password field the user just chose
    /// to use instead.
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
