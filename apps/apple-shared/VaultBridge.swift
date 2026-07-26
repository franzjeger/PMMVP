// Swift ↔ Rust bridge over vault-ffi (see crates/vault-ffi/include/vault_ffi.h).
//
// The Rust side owns all crypto; Swift only supplies the encrypted vault bytes
// (from the shared App Group container) and a key — either the device key from
// the shared keychain or the master password — then reads back login identities
// (metadata) and, on selection, one password. Shared by the host (populates the
// credential store) and the extension (fills). Secrets are copied straight into
// the platform credential and never retained.
//
// PORTABILITY: nothing here is macOS-only. An iOS app and its AutoFill
// extension link this file unchanged; the single platform difference (the
// data-protection keychain flag, which only macOS needs) is behind
// `#if os(macOS)`. See docs/IOS.md.
//
// CONCURRENCY: opening a vault blocks in three different ways — a keychain read
// that puts a Touch ID / Face ID prompt on screen and waits for the user, a file
// read, and (on the master-password path) Argon2id, which is *designed* to cost
// hundreds of milliseconds. None of it may run on the main actor: an AutoFill
// extension that wedges its main thread is killed by the watchdog rather than
// merely looking slow. So the handle lives behind a private serial queue and
// every entry point is `async`; callers stay on the main actor and `await`.
//
// A serial DispatchQueue rather than an `actor`, deliberately: actors run on the
// cooperative thread pool, which must not be blocked, and every call here blocks
// by nature. The queue also supplies the guarantee vault_ffi.h asks for —
// `vault_ffi_vault_free` never overlaps another call on the same handle.

import Foundation
import LocalAuthentication
import Security
import os

let vaultLog = Logger(subsystem: "no.sybr.vault.autofill", category: "vault")

/// App Group + keychain identifiers, shared with the Tauri Arca app.
enum VaultShared {
    static let appGroup = "group.no.sybr.vault"
    static let vaultFileName = "default.vault"
    static let keychainService = "no.sybr.vault"
    static let keychainAccount = "default-vault"

    /// The `ABI_VERSION` in crates/vault-ffi/src/lib.rs that this file was
    /// written against, enforced at open time. A static library from a different
    /// ABI would otherwise be called through the wrong signatures and fail
    /// quietly — and "quietly wrong" in a credential provider means filling the
    /// wrong bytes into someone's login form.
    static let requiredAbiVersion: Int32 = 5

    /// Info.plist key carrying the shared keychain access group. Both targets
    /// set it to `$(AppIdentifierPrefix)no.sybr.vault.shared`, which Xcode
    /// expands from the provisioning profile — so the team prefix is not pinned
    /// in source and building under a different team just works.
    private static let accessGroupInfoKey = "ArcaKeychainAccessGroup"

    /// Group name without the team prefix, as written in the entitlements.
    private static let accessGroupSuffix = "no.sybr.vault.shared"

    /// Prefix used only when the build had no profile to expand
    /// `$(AppIdentifierPrefix)` from (e.g. `CODE_SIGNING_ALLOWED=NO` in CI).
    /// Such a build cannot reach the shared keychain at all; this just keeps the
    /// query well-formed instead of silently searching the wrong group.
    private static let fallbackTeamPrefix = "LY6LJ395B8."

    /// Shared keychain access group holding the device (quick-unlock) key.
    /// Matches the `keychain-access-groups` entitlement on both targets.
    static let keychainAccessGroup: String = {
        let declared = Bundle.main
            .object(forInfoDictionaryKey: VaultShared.accessGroupInfoKey) as? String
        // An unexpanded "$(AppIdentifierPrefix)…", an empty string, or a bare
        // prefix-less group all mean the variable never got substituted.
        if let declared,
           !declared.isEmpty,
           !declared.contains("$("),
           declared != VaultShared.accessGroupSuffix {
            return declared
        }
        vaultLog.notice("keychain access group not resolved from Info.plist; using the built-in prefix")
        return VaultShared.fallbackTeamPrefix + VaultShared.accessGroupSuffix
    }()

    /// The encrypted vault file in the shared container, or `nil` if the App
    /// Group entitlement isn't provisioned.
    static var vaultURL: URL? {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: appGroup)?
            .appending(path: vaultFileName)
    }

    /// The encrypted vault file's bytes.
    static func loadVault() throws -> Data {
        guard let url = vaultURL else { throw VaultError.noContainer }
        let bytes: Data
        do {
            // Read and handle the failure, rather than `fileExists` then read:
            // the app rewrites this file atomically, so a stat-then-read races it.
            bytes = try Data(contentsOf: url)
        } catch let error as NSError {
            switch error.code {
            case NSFileReadNoSuchFileError, NSFileNoSuchFileError:
                throw VaultError.noVaultFile
            case NSFileReadNoPermissionError:
                throw VaultError.containerNotPermitted
            default:
                throw VaultError.unreadableVaultFile(code: error.code)
            }
        }
        // An empty `Data` has no base address, so this would reach the FFI as a
        // null pointer and come back as "null argument" — which reads like a
        // programming error rather than the broken vault file it actually is.
        guard !bytes.isEmpty else { throw VaultError.emptyVaultFile }
        return bytes
    }

    /// Replace the vault file.
    ///
    /// The one place that knows how this file gets written, because this is the
    /// user's only copy: atomically, so a failure mid-write leaves the previous
    /// vault intact rather than a truncated one, and — on iOS — unreadable while
    /// the device is locked. Everything that writes the container goes through
    /// here, so the options cannot drift between callers.
    static func writeVault(_ bytes: Data) throws {
        guard let url = vaultURL else { throw VaultError.noContainer }
        #if os(iOS)
        let options: Data.WritingOptions = [.atomic, .completeFileProtection]
        #else
        // completeFileProtection is iOS-only; macOS has no equivalent flag here.
        let options: Data.WritingOptions = [.atomic]
        #endif
        do {
            try bytes.write(to: url, options: options)
        } catch let error as NSError {
            throw error.code == NSFileWriteNoPermissionError
                ? VaultError.containerNotPermitted
                : VaultError.vaultWriteFailed(code: error.code)
        }
    }
}

/// Return codes from vault_ffi.h, named so nothing here carries a bare -7.
/// Mirrors the table at the top of that header; keep the two in step.
enum VaultFFICode {
    static let ok: Int32 = 0
    static let nullArgument: Int32 = -1
    static let invalidUTF8: Int32 = -2
    static let operationFailed: Int32 = -3
    static let locked: Int32 = -4
    static let notFound: Int32 = -5
    static let panicked: Int32 = -6
    static let decryptionFailed: Int32 = -7
    static let badKeyLength: Int32 = -8
}

/// Everything that can go wrong reaching or opening the shared vault.
///
/// Every case carries nothing but codes and OS status values — never key
/// material, the master password, or any decrypted item — so the whole type is
/// safe to log at `.public` privacy.
enum VaultError: Error, Equatable {
    /// A `vault-ffi` call returned a non-zero code; see the table in vault_ffi.h.
    case ffi(code: Int32, operation: String)
    /// The linked static library speaks a different ABI than this source.
    case abiMismatch(linked: Int32, expected: Int32)
    /// The App Group container could not be resolved (entitlement missing or
    /// not provisioned).
    case noContainer
    /// The container is there but the OS refused the read — the classic sign of
    /// an App Group entitlement that was never actually granted.
    case containerNotPermitted
    case noVaultFile
    /// A zero-byte vault file: present, but nothing to open.
    case emptyVaultFile
    case unreadableVaultFile(code: Int)
    /// The re-sealed vault could not be written back to the container.
    case vaultWriteFailed(code: Int)
    case noDeviceKey(status: OSStatus)
    /// The minted device key could not be put in the keychain. The vault file
    /// is already re-sealed by then, which is harmless — the master password
    /// still opens it and retrying replaces the wrapping.
    case deviceKeyNotStored(status: OSStatus)
    /// `vault_ffi_identities` returned something that wasn't the documented JSON.
    case malformedIdentities
}

extension VaultError: LocalizedError {
    var errorDescription: String? {
        switch self {
        case .ffi(let code, _) where code == VaultFFICode.decryptionFailed:
            return "That key doesn't open this vault. If you changed your master password, unlock Arca once on this Mac."
        case .ffi(let code, _) where code == VaultFFICode.notFound:
            return "That login is no longer in your vault."
        case .ffi, .malformedIdentities:
            return "Couldn't read your vault."
        case .abiMismatch:
            return "This build of Arca is mismatched with its vault library. Reinstall Arca."
        case .noContainer, .containerNotPermitted:
            return "Arca can't reach its shared container. Check that the App Group entitlement is provisioned."
        case .noVaultFile, .emptyVaultFile:
            return "No vault found. Set one up in Arca first."
        case .unreadableVaultFile:
            return "Couldn't read the vault file."
        case .vaultWriteFailed:
            return "Couldn't save the vault. Quick unlock is not set up."
        case .deviceKeyNotStored(let status) where status == errSecUserCanceled:
            return "Quick unlock was cancelled."
        case .deviceKeyNotStored:
            return "Couldn't store the quick-unlock key. Is Face ID or a passcode set up?"
        case .noDeviceKey(let status) where status == errSecUserCanceled:
            return "Unlock was cancelled."
        case .noDeviceKey(let status) where status == errSecItemNotFound:
            return "No quick-unlock key yet. Unlock Arca once on this Mac to create one."
        case .noDeviceKey:
            return "Couldn't unlock — Touch ID or the shared keychain isn't available."
        }
    }

    /// Short, stable, guaranteed secret-free — for `Logger`, not for people.
    var logMessage: String {
        switch self {
        case .ffi(let code, let operation): return "ffi(\(operation)=\(code))"
        case .abiMismatch(let linked, let expected): return "abiMismatch(\(linked)!=\(expected))"
        case .noContainer: return "noContainer"
        case .containerNotPermitted: return "containerNotPermitted"
        case .noVaultFile: return "noVaultFile"
        case .emptyVaultFile: return "emptyVaultFile"
        case .unreadableVaultFile(let code): return "unreadableVaultFile(\(code))"
        case .vaultWriteFailed(let code): return "vaultWriteFailed(\(code))"
        case .deviceKeyNotStored(let status): return "deviceKeyNotStored(\(status))"
        case .noDeviceKey(let status): return "noDeviceKey(\(status))"
        case .malformedIdentities: return "malformedIdentities"
        }
    }
}

/// Secret-free log text for any error crossing this bridge.
///
/// Deliberately not `String(describing:)`: an arbitrary error's description is
/// not something we control, and these lines are logged at `.public` privacy so
/// they survive into sysdiagnose.
func vaultLogMessage(for error: Error) -> String {
    if let error = error as? VaultError { return error.logMessage }
    let ns = error as NSError
    return "unexpected(\(ns.domain):\(ns.code))"
}

/// One login identity (metadata only) as produced by `vault_ffi_identities`.
struct VaultIdentity: Decodable, Sendable, Identifiable {
    let id: String
    let user: String
    let domain: String
    let label: String
}

/// An unlocked vault.
///
/// `@unchecked Sendable` because `OpaquePointer` isn't: the invariant that makes
/// it safe is that the handle is only ever touched inside `run`, which executes
/// on one shared serial queue — so no two FFI calls on a handle overlap, and the
/// free is ordered behind everything already queued for it.
final class VaultSession: @unchecked Sendable {

    /// Shared and serial. Shared so two simultaneous opens can't put two
    /// biometric prompts on screen; serial so the C ABI's non-overlap rule holds.
    private static let queue = DispatchQueue(label: "no.sybr.vault.session", qos: .userInitiated)

    private let handle: OpaquePointer

    private init(handle: OpaquePointer) { self.handle = handle }

    deinit {
        // Hand the raw pointer to the queue rather than `self`: `deinit` runs on
        // whichever thread dropped the last reference, and the free has to be
        // ordered behind any work already queued for this handle. Enqueuing it
        // does both, and lets `self` finish dying immediately.
        let box = HandleBox(handle: handle)
        Self.queue.async { vault_ffi_vault_free(box.handle) }
    }

    /// Carries a handle across to the queue. `@unchecked` because
    /// `OpaquePointer` isn't `Sendable`; sound here because exactly one enqueued
    /// block ever receives a given box, and it frees the handle and drops it.
    private struct HandleBox: @unchecked Sendable {
        let handle: OpaquePointer
    }

    // MARK: Opening

    /// Open the shared vault with the device (quick-unlock) key.
    ///
    /// Puts a Touch ID / Face ID prompt on screen and waits for the user, so it
    /// must not be called from a context that also has to draw.
    static func openWithDeviceKey(reason: String) async throws -> VaultSession {
        try await Self.run {
            try Self.checkAbi()
            let vaultBytes = try VaultShared.loadVault()
            return try Self.withDeviceKey(reason: reason) { key in
                var handle: OpaquePointer?
                let code = vaultBytes.withUnsafeBytes { vault in
                    key.withUnsafeBytes { deviceKey in
                        vault_ffi_vault_open(
                            vault.bindMemory(to: UInt8.self).baseAddress, vault.count,
                            deviceKey.bindMemory(to: UInt8.self).baseAddress, deviceKey.count,
                            &handle)
                    }
                }
                guard code == VaultFFICode.ok, let handle else {
                    throw VaultError.ffi(code: code, operation: "vault_open")
                }
                return VaultSession(handle: handle)
            }
        }
    }

    /// Open the shared vault with the **master password**.
    ///
    /// The path a client with no device key has to take — a phone on first
    /// launch, a recovery tool. Derives the key with Argon2id using the
    /// parameters in the vault's own header, so it is expensive by design; that
    /// cost is the reason this whole type is `async` rather than a convenience.
    static func openWithMasterPassword(_ password: String) async throws -> VaultSession {
        try await Self.run {
            try Self.checkAbi()
            let vaultBytes = try VaultShared.loadVault()
            var handle: OpaquePointer?
            let code = vaultBytes.withUnsafeBytes { vault in
                password.withCString { password in
                    vault_ffi_vault_open_password(
                        vault.bindMemory(to: UInt8.self).baseAddress, vault.count,
                        password, &handle)
                }
            }
            guard code == VaultFFICode.ok, let handle else {
                throw VaultError.ffi(code: code, operation: "vault_open_password")
            }
            return VaultSession(handle: handle)
        }
    }

    // MARK: Reading

    /// Login identities — metadata only, never a secret.
    func identities() async throws -> [VaultIdentity] {
        try await Self.run {
            var json: UnsafeMutablePointer<UInt8>?
            var length = 0
            let code = vault_ffi_identities(self.handle, &json, &length)
            guard code == VaultFFICode.ok else {
                throw VaultError.ffi(code: code, operation: "identities")
            }
            // (null, 0) is how the ABI represents an empty result.
            guard let json else { return [] }
            defer { vault_ffi_free(json, length) }
            do {
                return try JSONDecoder()
                    .decode([VaultIdentity].self, from: Data(bytes: json, count: length))
            } catch {
                // The decode error itself could quote the payload, so it is
                // swallowed rather than logged or wrapped.
                throw VaultError.malformedIdentities
            }
        }
    }

    /// The password for one identity, as the `String` the platform credential
    /// APIs require.
    ///
    /// The Rust buffer is zeroed by `vault_ffi_free` as soon as it is copied.
    /// The `String` cannot be wiped — Swift strings are immutable and the runtime
    /// may copy them — so hand it straight to `ASPasswordCredential` and keep no
    /// other reference to it.
    func password(forID id: String) async throws -> String {
        try await Self.run {
            var buffer: UnsafeMutablePointer<UInt8>?
            var length = 0
            let code = id.withCString {
                vault_ffi_password_for_id(self.handle, $0, &buffer, &length)
            }
            guard code == VaultFFICode.ok else {
                throw VaultError.ffi(code: code, operation: "password_for_id")
            }
            // (null, 0) is an empty password, not a failure.
            guard let buffer else { return "" }
            defer { vault_ffi_free(buffer, length) }
            // Decoded straight from the Rust buffer: going via `Data` first would
            // leave a second heap copy of the password behind that nothing zeroes.
            return String(decoding: UnsafeBufferPointer(start: buffer, count: length),
                          as: UTF8.self)
        }
    }

    // MARK: Quick unlock

    /// Turn on quick unlock: mint a device key, re-seal the vault with it, and
    /// put the key in the shared keychain behind Face ID / Touch ID.
    ///
    /// The order is not arbitrary. The vault file is written BEFORE the key is
    /// stored, because the two failure modes are not symmetric: a vault carrying
    /// a wrapping whose key was never saved is inert — the master password still
    /// opens it and running this again replaces the wrapping — whereas a stored
    /// key for a vault that was never written opens nothing, and every launch
    /// after it would prompt for a biometric and then fail.
    func enableDeviceUnlock() async throws {
        try await Self.run {
            var key: UnsafeMutablePointer<UInt8>?
            var keyLength = 0
            var vault: UnsafeMutablePointer<UInt8>?
            var vaultLength = 0
            let code = vault_ffi_enable_device_unlock(
                self.handle, &key, &keyLength, &vault, &vaultLength)
            guard code == VaultFFICode.ok, let key, let vault else {
                throw VaultError.ffi(code: code, operation: "enable_device_unlock")
            }
            // Rust zeroes both buffers; the device key half is a secret.
            defer {
                vault_ffi_free(key, keyLength)
                vault_ffi_free(vault, vaultLength)
            }

            try VaultShared.writeVault(Data(bytes: vault, count: vaultLength))

            var keyData = Data(bytes: key, count: keyLength)
            // Same best-effort wipe as the read path, and the same reason it is
            // only best-effort: `Data` is copy-on-write, so this clears the
            // buffer while nothing else holds it.
            defer { keyData.resetBytes(in: 0..<keyData.count) }
            try Self.storeDeviceKey(keyData)
        }
    }

    /// Insert or update a login, persisting the vault file.
    ///
    /// Pass `id` to edit an existing login, or nil to create one. The Rust side
    /// returns the whole new vault file; writing it is ours to do, and it lands
    /// atomically with file protection like every other write here.
    ///
    /// Returns the item's id, which is the caller's handle to it afterwards
    /// (the same id on an edit, a fresh one on a create).
    @discardableResult
    func upsertLogin(
        id: String? = nil,
        title: String,
        username: String,
        password: String,
        url: String,
        totpSecret: String? = nil,
        notes: String = ""
    ) async throws -> String {
        try await Self.run {
            var vault: UnsafeMutablePointer<UInt8>?
            var vaultLength = 0
            var idOut: UnsafeMutablePointer<UInt8>?
            var idLength = 0
            // Milliseconds since the epoch: vault-core has no clock, so the
            // timestamp is ours to supply.
            let now = Int64(Date().timeIntervalSince1970 * 1000)

            // withCString nests rather than composes; the pointers are only
            // valid inside their closures, so the call happens innermost.
            let code: Int32 = (id ?? "").withCString { idPtr in
                title.withCString { titlePtr in
                    username.withCString { userPtr in
                        password.withCString { passPtr in
                            url.withCString { urlPtr in
                                (totpSecret ?? "").withCString { totpPtr in
                                    notes.withCString { notesPtr in
                                        vault_ffi_upsert_login(
                                            self.handle, idPtr, titlePtr, userPtr,
                                            passPtr, urlPtr, totpPtr, notesPtr, now,
                                            &vault, &vaultLength, &idOut, &idLength)
                                    }
                                }
                            }
                        }
                    }
                }
            }
            guard code == VaultFFICode.ok, let vault, let idOut else {
                throw VaultError.ffi(code: code, operation: "upsert_login")
            }
            defer {
                vault_ffi_free(vault, vaultLength)
                vault_ffi_free(idOut, idLength)
            }
            // Persist BEFORE reporting success: an id for an item that never
            // reached disk would be a lie the UI acts on.
            try VaultShared.writeVault(Data(bytes: vault, count: vaultLength))
            return String(decoding: Data(bytes: idOut, count: idLength), as: UTF8.self)
        }
    }

    /// Soft-delete an item (it moves to the Trash, restorable on the desktop),
    /// persisting the vault file.
    func deleteItem(id: String) async throws {
        try await Self.run {
            var vault: UnsafeMutablePointer<UInt8>?
            var vaultLength = 0
            let now = Int64(Date().timeIntervalSince1970 * 1000)
            let code = id.withCString {
                vault_ffi_delete_item(self.handle, $0, now, &vault, &vaultLength)
            }
            guard code == VaultFFICode.ok, let vault else {
                throw VaultError.ffi(code: code, operation: "delete_item")
            }
            defer { vault_ffi_free(vault, vaultLength) }
            try VaultShared.writeVault(Data(bytes: vault, count: vaultLength))
        }
    }

    /// Turn quick unlock off.
    ///
    /// The keychain item goes first, so the key stops being usable the moment
    /// the user asks. Stripping the wrapping from the file matters too: deleting
    /// the key alone would leave the wrapping in the vault, where it travels to
    /// every device the vault syncs to.
    func disableDeviceUnlock() async throws {
        try await Self.run {
            Self.deleteDeviceKey()

            var vault: UnsafeMutablePointer<UInt8>?
            var vaultLength = 0
            let code = vault_ffi_disable_device_unlock(self.handle, &vault, &vaultLength)
            guard code == VaultFFICode.ok, let vault else {
                throw VaultError.ffi(code: code, operation: "disable_device_unlock")
            }
            defer { vault_ffi_free(vault, vaultLength) }
            try VaultShared.writeVault(Data(bytes: vault, count: vaultLength))
        }
    }

    /// Whether the VAULT carries a device-wrapped key.
    ///
    /// A different question from whether the keychain holds one, and worth
    /// asking separately: a key outlives the vault that accepted it if the file
    /// is replaced from a backup, and a client trusting only the keychain would
    /// prompt for a biometric and then fail to open anything.
    func hasDeviceUnlock() async -> Bool {
        let result = try? await Self.run {
            vault_ffi_has_device_unlock(self.handle) == 1
        }
        return result ?? false
    }

    // MARK: Plumbing

    /// Run blocking work on the vault queue and `await` it.
    ///
    /// Not cancellable: neither the biometric prompt nor Argon2id can be
    /// interrupted once started, so pretending otherwise would be a lie. They are
    /// bounded — the prompt by the user, the KDF by the header's parameters.
    private static func run<T: Sendable>(
        _ work: @escaping @Sendable () throws -> T
    ) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                continuation.resume(with: Result { try work() })
            }
        }
    }

    /// Fail closed if the linked static library is a different ABI than this
    /// source was written against.
    private static func checkAbi() throws {
        let linked = vault_ffi_abi_version()
        guard linked == VaultShared.requiredAbiVersion else {
            throw VaultError.abiMismatch(linked: linked, expected: VaultShared.requiredAbiVersion)
        }
    }

    /// Base keychain query identifying the one device-key item. Shared by every
    /// operation on it, so the four attributes that decide *which* item is
    /// touched cannot drift between read, write, delete and probe.
    private static func deviceKeyQuery() -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: VaultShared.keychainService,
            kSecAttrAccount as String: VaultShared.keychainAccount,
            kSecAttrAccessGroup as String: VaultShared.keychainAccessGroup,
        ]
        #if os(macOS)
        // Arca writes the device key into the DATA-PROTECTION keychain, which is
        // the one that carries access groups and biometric access control.
        // Without this flag the query hits the file-based login keychain and
        // finds nothing. iOS has only the data-protection keychain.
        query[kSecUseDataProtectionKeychain as String] = true
        #endif
        return query
    }

    /// Store the device key, replacing whatever was there.
    private static func storeDeviceKey(_ key: Data) throws {
        // Replace rather than add: `SecItemAdd` over an existing item fails with
        // errSecDuplicateItem, and a leftover key from a previous enrolment
        // would unlock nothing.
        deleteDeviceKey()

        // `biometryCurrentSet` invalidates the key when a face or finger is
        // added, which is the defence against someone who has the passcode
        // enrolling their own biometrics. It cannot be satisfied on a device
        // with none enrolled, so fall back to `userPresence` there — the master
        // password is the backstop either way.
        let context = LAContext()
        let hasBiometrics = context.canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics, error: nil)
        let flags: SecAccessControlCreateFlags =
            hasBiometrics ? .biometryCurrentSet : .userPresence

        // WhenUnlockedThisDeviceOnly: the key is for THIS device, so it must
        // never reach a backup or another device via iCloud Keychain.
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            nil)
        else {
            throw VaultError.deviceKeyNotStored(status: errSecParam)
        }

        var query = deviceKeyQuery()
        // kSecAttrAccessControl carries the accessibility itself; setting
        // kSecAttrAccessible alongside it is rejected.
        query[kSecAttrAccessControl as String] = access
        query[kSecValueData as String] = key

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw VaultError.deviceKeyNotStored(status: status)
        }
    }

    /// Remove the device key. Missing is success — the caller wants it gone.
    private static func deleteDeviceKey() {
        _ = SecItemDelete(deviceKeyQuery() as CFDictionary)
    }

    /// Forget the stored device key without an open vault to strip the wrapping
    /// from. For when the vault FILE is replaced: the key was minted for a file
    /// that no longer exists, and leaving it would offer a biometric unlock that
    /// cannot possibly work.
    static func forgetDeviceKey() { deleteDeviceKey() }

    /// Whether a device key is stored, WITHOUT prompting for it.
    ///
    /// Asking for the data would put a Face ID sheet on screen to answer what is
    /// only a question about which button to draw. Querying attributes needs no
    /// authentication; if the OS insists anyway it says so, and that is still a
    /// yes.
    static var hasStoredDeviceKey: Bool {
        var query = deviceKeyQuery()
        query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    /// Read the device key from the shared keychain group, gated by Touch ID /
    /// Face ID / the device passcode, and hand it to `body`.
    ///
    /// Scoped rather than returned so no copy of the key outlives the open it was
    /// read for. The wipe is best-effort: `Data` is copy-on-write, so it clears
    /// the buffer only while this is the last reference — which is precisely why
    /// the key never leaves this function.
    private static func withDeviceKey<T>(reason: String, _ body: (Data) throws -> T) throws -> T {
        let context = LAContext()
        context.localizedReason = reason
        // Never reuse an earlier authentication: every vault open is its own
        // deliberate act. Zero is the default; stated so it cannot drift.
        context.touchIDAuthenticationAllowableReuseDuration = 0
        defer { context.invalidate() }

        var query = deviceKeyQuery()
        query[kSecReturnData as String] = true
        query[kSecUseAuthenticationContext as String] = context

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, var key = result as? Data else {
            throw VaultError.noDeviceKey(status: status)
        }
        defer { key.resetBytes(in: 0..<key.count) }
        return try body(key)
    }
}
