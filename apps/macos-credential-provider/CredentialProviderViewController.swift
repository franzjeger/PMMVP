// SYBR Passwords — macOS AutoFill Credential Provider (passkeys).
//
// SCAFFOLD. This is the OS-facing half of passkey support: the extension macOS
// loads so SYBR Passwords appears in the system "Choose where to save your
// passkey" / passkey chooser. It drives the ASCredentialProviderExtension
// passkey flow and calls the Rust `vault-ffi` C ABI (see
// crates/vault-ffi/include/vault_ffi.h) for the ES256 authenticator work.
//
// It does NOT build as-is: it needs an Xcode target with the
// `com.apple.developer.authentication-services.autofill-credential-provider`
// entitlement, a shared App Group (group.no.sybr.vault) with the main app, and
// the vault-ffi static library linked in. See ./README.md and docs/PASSKEYS.md.
//
// The parts marked TODO(vault-access) require the additional vault-open FFI
// (read the encrypted vault + device key from the shared App Group container);
// that surface is intentionally not built yet.

import AuthenticationServices
import Foundation

@available(macOS 14.0, *)
final class CredentialProviderViewController: ASCredentialProviderViewController {

    // MARK: Passkey registration (navigator.credentials.create)

    override func prepareInterface(forPasskeyRegistration registrationRequest: ASCredentialRequest) {
        guard let request = registrationRequest as? ASPasskeyCredentialRequest,
              let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity
        else {
            cancel(.failed)
            return
        }
        let rpId = identity.relyingPartyIdentifier

        // The OS performs user verification (Touch ID) as part of this flow.
        var credId: UnsafeMutablePointer<UInt8>? = nil
        var credIdLen = 0
        var privKey: UnsafeMutablePointer<UInt8>? = nil
        var privKeyLen = 0
        var att: UnsafeMutablePointer<UInt8>? = nil
        var attLen = 0

        let rc = rpId.withCString {
            vault_ffi_passkey_create($0,
                                     &credId, &credIdLen,
                                     &privKey, &privKeyLen,
                                     &att, &attLen)
        }
        guard rc == 0, let credId, let privKey, let att else {
            cancel(.failed)
            return
        }
        defer {
            vault_ffi_free(credId, credIdLen)
            vault_ffi_free(privKey, privKeyLen)
            vault_ffi_free(att, attLen)
        }

        let credentialID = Data(bytes: credId, count: credIdLen)
        let attestationObject = Data(bytes: att, count: attLen)
        let privateKey = Data(bytes: privKey, count: privKeyLen)

        // TODO(vault-access): persist {rpId, identity.userName, identity.userHandle,
        // credentialID, privateKey, signCount = 0} into the encrypted vault via
        // the vault-open FFI + App Group container. Without this, the credential
        // cannot be used for a later assertion.
        _ = privateKey

        let credential = ASPasskeyRegistrationCredential(
            relyingParty: rpId,
            clientDataHash: request.clientDataHash,
            credentialID: credentialID,
            attestationObject: attestationObject)

        extensionContext.completeRegistrationRequest(using: credential)
    }

    // MARK: Passkey assertion (navigator.credentials.get)

    override func provideCredentialWithoutUserInteraction(for credentialRequest: ASCredentialRequest) {
        guard let request = credentialRequest as? ASPasskeyCredentialRequest,
              let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity
        else {
            cancel(.failed)
            return
        }

        // TODO(vault-access): look up the stored passkey by
        // identity.credentialID within the (unlocked) vault and read its private
        // key + current signCount. If the vault is locked, throw
        // .userInteractionRequired so the OS shows our UI to unlock (Touch ID).
        guard let stored = loadPasskey(credentialID: identity.credentialID) else {
            cancel(.userInteractionRequired)
            return
        }

        let rpId = identity.relyingPartyIdentifier
        let clientDataHash = request.clientDataHash

        var authData: UnsafeMutablePointer<UInt8>? = nil
        var authDataLen = 0
        var sig: UnsafeMutablePointer<UInt8>? = nil
        var sigLen = 0

        let rc = stored.privateKey.withUnsafeBytes { keyBuf in
            clientDataHash.withUnsafeBytes { hashBuf in
                rpId.withCString { rpPtr in
                    vault_ffi_passkey_assert(
                        keyBuf.bindMemory(to: UInt8.self).baseAddress,
                        keyBuf.count,
                        rpPtr,
                        hashBuf.bindMemory(to: UInt8.self).baseAddress,
                        hashBuf.count,
                        &authData, &authDataLen,
                        &sig, &sigLen)
                }
            }
        }
        guard rc == 0, let authData, let sig else {
            cancel(.failed)
            return
        }
        defer {
            vault_ffi_free(authData, authDataLen)
            vault_ffi_free(sig, sigLen)
        }

        let credential = ASPasskeyAssertionCredential(
            userHandle: stored.userHandle,
            relyingParty: rpId,
            signature: Data(bytes: sig, count: sigLen),
            clientDataHash: clientDataHash,
            authenticatorData: Data(bytes: authData, count: authDataLen),
            credentialID: identity.credentialID)

        extensionContext.completeAssertionRequest(using: credential)
    }

    private func cancel(_ code: ASExtensionError.Code) {
        extensionContext.cancelRequest(withError: ASExtensionError(code))
    }

    // MARK: - vault access (not yet implemented)

    private struct StoredPasskey {
        let privateKey: Data
        let userHandle: Data
    }

    /// TODO(vault-access): read from the encrypted vault in the shared App Group
    /// container, unlocked via the OS-keychain device key. Returns nil today.
    private func loadPasskey(credentialID: Data) -> StoredPasskey? {
        _ = credentialID
        return nil
    }
}
