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
    static let requiredAbiVersion: Int32 = 3

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
    case noDeviceKey(status: OSStatus)
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
            let vaultBytes = try Self.loadVaultBytes()
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
            let vaultBytes = try Self.loadVaultBytes()
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

    /// The encrypted vault file's bytes.
    private static func loadVaultBytes() throws -> Data {
        guard let url = VaultShared.vaultURL else { throw VaultError.noContainer }
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

        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: VaultShared.keychainService,
            kSecAttrAccount as String: VaultShared.keychainAccount,
            kSecAttrAccessGroup as String: VaultShared.keychainAccessGroup,
            kSecReturnData as String: true,
            kSecUseAuthenticationContext as String: context,
        ]
        #if os(macOS)
        // Arca writes the device key into the DATA-PROTECTION keychain, which is
        // the one that carries access groups and the Touch ID access control.
        // Without this flag the search hits the file-based login keychain and
        // finds nothing. iOS has only the data-protection keychain and ignores
        // the key, so it is scoped to macOS to keep the query honest.
        query[kSecUseDataProtectionKeychain as String] = true
        #endif

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, var key = result as? Data else {
            throw VaultError.noDeviceKey(status: status)
        }
        defer { key.resetBytes(in: 0..<key.count) }
        return try body(key)
    }
}
