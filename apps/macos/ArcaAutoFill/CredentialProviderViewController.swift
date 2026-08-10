// Arca — macOS AutoFill Credential Provider (passwords), M2 real vault.
//
// Fills the user's ACTUAL passwords: opens the shared vault via the Rust FFI
// (Touch ID reads the device key from the shared keychain), then returns the
// selected credential. The password is copied straight into ASPasswordCredential
// and never retained. Reading the key is user interaction, so the quick-fill
// (no-UI) entry point defers to the UI entry point where the Touch ID prompt is
// expected.
//
// Every vault call is awaited, never blocking: `VaultSession` does the keychain
// read, the file read and the decrypt on its own queue. The main actor stays
// free to draw while the Touch ID prompt is up — an extension that wedges its
// main thread gets killed rather than merely looking slow.

import AuthenticationServices
import SwiftUI
import os

private let log = Logger(subsystem: "no.sybr.vault.autofill", category: "provider")

/// Shown by macOS as "Arca is trying to <reason>".
private let unlockReason = "unlock your Arca vault"

final class CredentialProviderViewController: ASCredentialProviderViewController {

    /// The picker's hosting controller, kept so a repeat `prepareCredentialList`
    /// replaces the list rather than stacking a second one over the first.
    private var listHost: NSHostingController<CredentialListView>?

    /// One vault open at a time: overlapping requests would race two Touch ID
    /// prompts onto the screen.
    private var isWorking = false

    // MARK: Quick fill (no UI)

    // We must prompt Touch ID to read the vault key, which counts as user
    // interaction — so ask the OS to show our UI path instead of filling silently.
    override func provideCredentialWithoutUserInteraction(for credentialRequest: ASCredentialRequest) {
        log.info("provideWithoutUI -> userInteractionRequired")
        cancel(.userInteractionRequired)
    }

    // MARK: UI path (Touch ID happens here)

    override func prepareInterfaceToProvideCredential(for credentialRequest: ASCredentialRequest) {
        // Passkeys have been available to third-party providers on macOS since
        // Sonoma (ASPasskeyCredentialRequest is macos(14.0)); Arca simply had
        // not implemented them, and the capability was left off so it would not
        // appear in the chooser and fail.
        if let request = credentialRequest as? ASPasskeyCredentialRequest {
            guard let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity,
                  let recordID = identity.recordIdentifier
            else {
                cancel(.credentialIdentityNotFound)
                return
            }
            Task {
                await assertPasskey(
                    recordID: recordID,
                    clientDataHash: request.clientDataHash,
                    rpID: identity.relyingPartyIdentifier)
            }
            return
        }
        guard credentialRequest.type == .password,
              let identity = credentialRequest.credentialIdentity as? ASPasswordCredentialIdentity,
              let recordID = identity.recordIdentifier
        else {
            cancel(.credentialIdentityNotFound)
            return
        }
        Task { await fill(recordID: recordID, user: identity.user) }
    }

    // The user opened the AutoFill list manually: show matching logins.
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        let domains = Set(serviceIdentifiers.map { $0.identifier.lowercased() })
        Task { await presentList(matching: domains) }
    }

    // MARK: Helpers

    @MainActor
    private func fill(recordID: String, user: String) async {
        guard !isWorking else { return }
        isWorking = true
        defer { isWorking = false }

        do {
            let session = try await VaultSession.openWithDeviceKey(reason: unlockReason)
            let password = try await session.password(forID: recordID)
            // The SHAPE of what we hand over, never the value.
            //
            // Without this there was no way to tell a fill that delivered the
            // wrong thing from a page that mangled the right thing: the whole
            // path from "Safari asked" to "the field has the wrong contents"
            // was unobserved, and every explanation for a bad fill was equally
            // consistent with the evidence. A length and a character count are
            // enough to settle it and reveal nothing.
            log.info(
                """
                fill user=\(user.count, privacy: .public)ch \
                password=\(password.count, privacy: .public)ch \
                ascii=\(password.allSatisfy(\.isASCII), privacy: .public) \
                record=\(recordID, privacy: .public)
                """)
            extensionContext.completeRequest(
                withSelectedCredential: ASPasswordCredential(user: user, password: password))
        } catch {
            log.error("fill failed: \(vaultLogMessage(for: error), privacy: .public)")
            cancel(.userCanceled)
        }
    }

    /// Sign the relying party's challenge with a stored passkey.
    ///
    /// `userVerified: true` is earned: opening the vault took Touch ID (or the
    /// master password), and both are user verification in WebAuthn's sense.
    /// The flag lands in the authenticator data the relying party trusts, so
    /// claiming it without the prompt would be lying to the site.
    @MainActor
    private func assertPasskey(recordID: String, clientDataHash: Data, rpID: String) async {
        guard !isWorking else { return }
        isWorking = true
        defer { isWorking = false }

        do {
            let session = try await VaultSession.openWithDeviceKey(reason: unlockReason)
            let assertion = try await session.assertPasskey(
                forID: recordID, clientDataHash: clientDataHash, userVerified: true)
            await extensionContext.completeAssertionRequest(
                using: ASPasskeyAssertionCredential(
                    userHandle: assertion.userHandle,
                    relyingParty: rpID,
                    signature: assertion.signature,
                    clientDataHash: clientDataHash,
                    authenticatorData: assertion.authenticatorData,
                    credentialID: assertion.credentialID))
        } catch {
            log.error("passkey assert failed: \(vaultLogMessage(for: error), privacy: .public)")
            cancel(.userCanceled)
        }
    }

    @MainActor
    private func presentList(matching domains: Set<String>) async {
        guard !isWorking else { return }
        isWorking = true
        defer { isWorking = false }

        var identities: [VaultIdentity] = []
        var failure: String?
        do {
            let session = try await VaultSession.openWithDeviceKey(reason: unlockReason)
            identities = try await session.identities()
                .filter { domains.isEmpty || domains.contains($0.domain) }
        } catch {
            // Say what actually went wrong — "couldn't open your vault" sends
            // people looking for a broken vault when the usual cause is a
            // missing quick-unlock key or a cancelled prompt.
            failure = (error as? VaultError)?.errorDescription ?? "Couldn't open your vault."
            log.error("list open failed: \(vaultLogMessage(for: error), privacy: .public)")
        }

        let asked = domains.sorted().joined(separator: ",")
        log.info(
            "list domains=\(asked, privacy: .public) matches=\(identities.count, privacy: .public)")
        show(CredentialListView(
            identities: identities,
            failure: failure,
            // SwiftUI calls these on the main actor already, so the hop costs
            // nothing — and unlike `MainActor.assumeIsolated` it cannot trap if
            // that ever stops being true.
            onPick: { [weak self] identity in
                Task { @MainActor in
                    await self?.fill(recordID: identity.id, user: identity.user)
                }
            },
            onCancel: { [weak self] in
                Task { @MainActor in self?.cancel(.userCanceled) }
            }))
    }

    /// Install the picker, or refresh the one already installed.
    @MainActor
    private func show(_ list: CredentialListView) {
        if let listHost {
            listHost.rootView = list
            return
        }
        let host = NSHostingController(rootView: list)
        listHost = host
        addChild(host)
        host.view.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(host.view)
        NSLayoutConstraint.activate([
            host.view.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            host.view.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            host.view.topAnchor.constraint(equalTo: view.topAnchor),
            host.view.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
    }

    // MARK: Doors this extension declared and never answered

    // Info.plist promises the system ProvidesPasswords AND ProvidesPasskeys.
    // Sign-in with a stored passkey works. REGISTERING one does not, and the
    // entry point for it was simply absent — which is not the same as absent.
    //
    // Every method this class does not override inherits Apple's default, and
    // that default DOES NOTHING: it neither completes the request nor cancels
    // it. So "save a passkey → choose Arca" presented this view controller,
    // called a method that answers nothing, and left the sheet on screen
    // forever. The app had not crashed and was not busy; it was never going to
    // reply.
    //
    // Cancelling is not the good outcome — the good outcome is registering the
    // passkey, and that is worth building. But an error the user can act on
    // beats a window they have to force-quit, and declaring a capability the
    // code cannot service is the actual defect either way.

    /// Register a new passkey from the system UI. Not implemented here; the
    /// browser extension is the working route on macOS today.
    override func prepareInterface(forPasskeyRegistration registrationRequest: ASCredentialRequest) {
        log.error("passkey registration is not implemented in this extension")
        cancel(.failed)
    }

    /// The user picked Arca from a system configuration flow. Nothing to
    /// configure in a sheet — the vault lives in the app — but this MUST
    /// complete, because completing is what dismisses it.
    override func prepareInterfaceForExtensionConfiguration() {
        log.info("extension configuration requested; completing")
        extensionContext.completeExtensionConfigurationRequest()
    }

    /// One-time codes. `ProvidesOneTimeCodes` is not declared, so the system
    /// should never ask — and "should never" is exactly the assumption that
    /// left the other sheet hanging.
    @available(macOS 15.0, *)
    override func prepareOneTimeCodeCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        log.error("one-time code list requested but not supported")
        cancel(.failed)
    }

    @MainActor
    private func cancel(_ code: ASExtensionError.Code) {
        extensionContext.cancelRequest(withError: ASExtensionError(code))
    }
}
