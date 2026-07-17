// Arca — macOS AutoFill Credential Provider (passwords), M1 skeleton.
//
// This is the OS-facing extension the system loads when a user picks an Arca
// suggestion in Safari / a native app. In M1 it serves ONE hardcoded test
// credential so we can prove the end-to-end OS integration before wiring the
// real vault (that is M2). No real secret and no vault/FFI access is involved.
//
// Flow:
//  - The host app publishes a test identity to ASCredentialIdentityStore.
//  - The OS shows it as an AutoFill suggestion for example.com.
//  - When the user picks it, the OS calls provideCredentialWithoutUserInteraction
//    (quick fill) or, if it shows our UI, prepareInterfaceToProvideCredential /
//    prepareCredentialList.
//  - We hand back an ASPasswordCredential and the field fills.

import AuthenticationServices
import SwiftUI

// Must match the identity the host app registers.
enum M1Credential {
    static let recordID = "arca-m1-test"
    static let domain = "example.com"
    static let user = "arca-test"
    // NOT a real secret: a fixed placeholder so M1 can demonstrate a fill.
    static let password = "arca-m1-demo"
}

final class CredentialProviderViewController: ASCredentialProviderViewController {

    // MARK: Quick fill (no UI)

    // Called when the OS wants the credential with no interaction (e.g. the user
    // tapped our inline Safari suggestion). M1 has nothing to unlock, so we can
    // answer immediately. In M2 this returns .userInteractionRequired when the
    // vault is locked, so the OS then shows our unlock UI.
    override func provideCredentialWithoutUserInteraction(for credentialRequest: ASCredentialRequest) {
        guard credentialRequest.type == .password,
              credentialRequest.credentialIdentity.recordIdentifier == M1Credential.recordID
        else {
            extensionContext.cancelRequest(
                withError: ASExtensionError(.credentialIdentityNotFound))
            return
        }
        completeWithTestCredential()
    }

    // MARK: UI paths

    // The OS shows our extension UI and asks us to provide a specific credential.
    override func prepareInterfaceToProvideCredential(for credentialRequest: ASCredentialRequest) {
        presentList()
    }

    // The user opened the AutoFill list manually.
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        presentList()
    }

    // MARK: Helpers

    private func presentList() {
        let view = CredentialListView(
            user: M1Credential.user,
            domain: M1Credential.domain,
            onPick: { [weak self] in self?.completeWithTestCredential() },
            onCancel: { [weak self] in
                self?.extensionContext.cancelRequest(
                    withError: ASExtensionError(.userCanceled))
            })
        let host = NSHostingController(rootView: view)
        addChild(host)
        host.view.translatesAutoresizingMaskIntoConstraints = false
        self.view.addSubview(host.view)
        NSLayoutConstraint.activate([
            host.view.leadingAnchor.constraint(equalTo: self.view.leadingAnchor),
            host.view.trailingAnchor.constraint(equalTo: self.view.trailingAnchor),
            host.view.topAnchor.constraint(equalTo: self.view.topAnchor),
            host.view.bottomAnchor.constraint(equalTo: self.view.bottomAnchor),
        ])
    }

    private func completeWithTestCredential() {
        let credential = ASPasswordCredential(
            user: M1Credential.user, password: M1Credential.password)
        extensionContext.completeRequest(withSelectedCredential: credential)
    }
}
