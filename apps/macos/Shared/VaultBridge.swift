// Swift ↔ Rust bridge over vault-ffi (see crates/vault-ffi/include/vault_ffi.h).
//
// The Rust side owns all crypto; Swift only supplies the encrypted vault bytes
// (from the shared App Group container) and the device key (from the shared
// keychain), then reads back login identities (metadata) and, on selection, one
// password. Shared by the host (populates the credential store) and the
// extension (fills). Secrets are copied straight into the platform credential
// and never retained.

import Foundation
import LocalAuthentication
import os

let vaultLog = Logger(subsystem: "no.sybr.vault.autofill", category: "vault")

/// App Group + keychain identifiers, shared with the Tauri Arca app.
enum VaultShared {
    static let appGroup = "group.no.sybr.vault"
    static let vaultFileName = "default.vault"
    static let keychainService = "no.sybr.vault"
    static let keychainAccount = "default-vault"

    /// The encrypted vault file in the shared container (nil if the entitlement
    /// isn't provisioned yet).
    static var vaultURL: URL? {
        FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: appGroup)?
            .appendingPathComponent(vaultFileName)
    }
}

enum VaultError: Error {
    case ffi(Int32)
    case noVaultFile
    case noDeviceKey(OSStatus)
    case decode
}

/// One login identity (metadata only) as produced by vault_ffi_identities.
struct VaultIdentity: Decodable {
    let id: String
    let user: String
    let domain: String
    let label: String
}

/// The vault-ffi ABI version this build linked against (linkage smoke check).
func vaultFfiAbiVersion() -> Int32 { vault_ffi_abi_version() }

/// Read the device (quick-unlock) key from the shared keychain group, gated by
/// Touch ID / the device passcode. Returns the raw 32-byte key.
func deviceKey(reason: String) throws -> Data {
    let ctx = LAContext()
    ctx.localizedReason = reason
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: VaultShared.keychainService,
        kSecAttrAccount as String: VaultShared.keychainAccount,
        kSecReturnData as String: true,
        kSecUseAuthenticationContext as String: ctx,
    ]
    var out: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &out)
    guard status == errSecSuccess, let data = out as? Data else {
        throw VaultError.noDeviceKey(status)
    }
    return data
}

/// A Swift owner of an unlocked vault handle. Frees (locks + zeroizes) on deinit.
final class OpenVault {
    private let handle: OpaquePointer

    private init(handle: OpaquePointer) { self.handle = handle }

    /// Open + unlock the shared vault file with the device key.
    static func open() throws -> OpenVault {
        guard let url = VaultShared.vaultURL,
              FileManager.default.fileExists(atPath: url.path)
        else { throw VaultError.noVaultFile }
        let vaultData = try Data(contentsOf: url)
        let key = try deviceKey(reason: "unlock your Arca vault")
        defer { /* key is a local Data; dropped at scope end */ }

        var handlePtr: OpaquePointer?
        let rc = vaultData.withUnsafeBytes { vp in
            key.withUnsafeBytes { kp in
                vault_ffi_vault_open(
                    vp.bindMemory(to: UInt8.self).baseAddress, vaultData.count,
                    kp.bindMemory(to: UInt8.self).baseAddress, key.count,
                    &handlePtr)
            }
        }
        guard rc == 0, let handlePtr else { throw VaultError.ffi(rc) }
        return OpenVault(handle: handlePtr)
    }

    /// Login identities (metadata only) for populating the credential store.
    func identities() throws -> [VaultIdentity] {
        var json: UnsafeMutablePointer<UInt8>?
        var len = 0
        let rc = vault_ffi_identities(handle, &json, &len)
        guard rc == 0, let json else { throw VaultError.ffi(rc) }
        defer { vault_ffi_free(json, len) }
        let data = Data(bytes: json, count: len)
        guard let ids = try? JSONDecoder().decode([VaultIdentity].self, from: data)
        else { throw VaultError.decode }
        return ids
    }

    /// The password for one identity id. Copy it into the credential and drop it.
    func password(forId id: String) throws -> String {
        var pw: UnsafeMutablePointer<UInt8>?
        var len = 0
        let rc = id.withCString { vault_ffi_password_for_id(handle, $0, &pw, &len) }
        guard rc == 0 else { throw VaultError.ffi(rc) }
        guard let pw else { return "" } // empty password → (null, 0)
        defer { vault_ffi_free(pw, len) }
        return String(decoding: Data(bytes: pw, count: len), as: UTF8.self)
    }

    deinit { vault_ffi_vault_free(handle) }
}
