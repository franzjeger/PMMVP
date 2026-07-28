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

    /// Whether a quick-unlock key is stored on this device.
    ///
    /// Cached, not computed. It used to call straight into the keychain, and it
    /// is read from inside `UnlockView.body` — so on a device, where every probe
    /// is a synchronous XPC to securityd that also has to consult a biometric
    /// access control, it ran again on every keystroke in the password field.
    /// Three things change the answer, and all three refresh it themselves.
    private(set) var quickUnlockAvailable = false

    /// Held only while unlocked.
    private var session: VaultSession?
    /// The sync engine, alive for as long as the session it wraps.
    private var sync: VaultSync?
    /// Last known sync state, for the UI. `nil` until asked.
    private(set) var syncStatus: SyncStatus?
    private(set) var syncing = false

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
        refreshQuickUnlockAvailability()
    }

    /// Re-probe the keychain off the main actor and publish the answer.
    ///
    /// Off the main actor because it is a blocking XPC round-trip: cheap in the
    /// simulator, not on a phone. Called from the three places that can change
    /// the answer — appearing, enabling, and forgetting the key — rather than
    /// from a view body.
    private func refreshQuickUnlockAvailability() {
        Task.detached(priority: .userInitiated) {
            let stored = VaultSession.hasStoredDeviceKey
            await MainActor.run { self.quickUnlockAvailable = stored }
        }
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
            // Sync last: it is network-bound and nobody should wait behind it to
            // see their own vault.
            await startSync(session)
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
            refreshQuickUnlockAvailability()
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
            refreshQuickUnlockAvailability()
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
        sync = nil
        syncStatus = nil
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

    /// Create or update a login, then refresh the list and the AutoFill store.
    ///
    /// Returns nil on success, or a message to show in the editor. The error
    /// goes back to the caller instead of only into `failure` because the sheet
    /// stays open on failure, and a banner behind it would not be read.
    func saveLogin(
        id: String?,
        title: String,
        username: String,
        password: String,
        url: String
    ) async -> String? {
        guard let session else { return "The vault is locked." }
        do {
            try await session.upsertLogin(
                id: id, title: title, username: username,
                password: password, url: url)
            // The identity list and the credential store both describe the vault
            // we just changed; leaving either stale means the keyboard offers
            // yesterday's logins.
            await reload(session)
            // Tell the engine there is something to push; the next cycle sends it.
            await sync?.markDirty()
            return nil
        } catch {
            log.error("save login failed: \(vaultLogMessage(for: error), privacy: .public)")
            return Self.message(error, fallback: "Couldn't save that login.")
        }
    }

    /// Move a login to the Trash (restorable on the desktop).
    func deleteLogin(_ identity: VaultIdentity) async {
        guard let session else { return }
        do {
            try await session.deleteItem(id: identity.id)
            await reload(session)
        } catch {
            log.error("delete failed: \(vaultLogMessage(for: error), privacy: .public)")
            failure = Self.message(error, fallback: "Couldn't delete that login.")
        }
    }

    /// Re-read the identities and republish them to AutoFill after a write.
    ///
    /// Same ordering as the unlock path, so a save does not silently reshuffle
    /// the list under the user.
    private func reload(_ session: VaultSession) async {
        do {
            let fresh = try await session.identities()
            identities = fresh.sorted {
                ($0.domain.lowercased(), $0.user.lowercased())
                    < ($1.domain.lowercased(), $1.user.lowercased())
            }
            autoFillEnabled = await CredentialIdentities.replace(with: identities)
        } catch {
            log.error("reload failed: \(vaultLogMessage(for: error), privacy: .public)")
            failure = Self.message(error, fallback: "Saved, but the list is out of date.")
        }
    }

    // MARK: - Sync

    /// Whether a Google credential is stored on this device (no keychain read).
    var syncConnected: Bool { SyncCredentialStore.exists }

    /// Build the engine for a freshly opened vault and, if this device is
    /// already signed in, reconnect and pull.
    private func startSync(_ session: VaultSession) async {
        do {
            let engine = try await session.makeSync()
            sync = engine
            guard let token = SyncCredentialStore.load() else { return }
            try await engine.connect(refreshToken: token, account: nil)
            await runSync()
        } catch {
            // A sync that cannot start must never block using the vault.
            log.error("sync start failed: \(vaultLogMessage(for: error), privacy: .public)")
        }
    }

    /// Run one cycle and fold the result into the UI.
    func runSync() async {
        guard let sync, !syncing else { return }
        syncing = true
        defer { syncing = false }
        do {
            let status = try await sync.syncNow()
            syncStatus = status
            // A merge rewrote the vault file AND the shared in-memory vault, so
            // the list on screen is now behind what the engine already holds.
            if status.merged, let session { await reload(session) }
            if let message = status.lastError { failure = message }
        } catch {
            log.error("sync failed: \(vaultLogMessage(for: error), privacy: .public)")
            failure = Self.message(error, fallback: "Sync failed.")
        }
    }

    /// Sign in to Google and start syncing. The consent screen is presented by
    /// `SyncSignIn`; the PKCE verifier never leaves Rust.
    func connectSync() async {
        guard let sync else { return }
        syncing = true
        defer { syncing = false }
        do {
            let (token, account) = try await SyncSignIn().run()
            // Store BEFORE connecting: a token the engine uses but that was
            // never persisted works until the app quits and then silently stops.
            try SyncCredentialStore.save(token)
            try await sync.connect(refreshToken: token, account: account)
            await runSync()
        } catch SyncError.cancelled {
            // The user closed the sheet. Not an error.
        } catch {
            log.error("sync connect failed: \(vaultLogMessage(for: error), privacy: .public)")
            failure = Self.message(error, fallback: "Couldn't connect to Google.")
        }
    }

    /// Stop syncing and forget the credential on this device. The vault itself
    /// and the copy in Drive are both left alone.
    func disconnectSync() async {
        do {
            try await sync?.disconnect()
        } catch {
            log.error("sync disconnect failed: \(vaultLogMessage(for: error), privacy: .public)")
        }
        // Delete the token even if the engine call failed, or the next launch
        // would reconnect to an account the user just asked to forget.
        SyncCredentialStore.delete()
        syncStatus = nil
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
            refreshQuickUnlockAvailability()
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
