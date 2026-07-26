// Arca — iOS AutoFill Credential Provider (passwords). SCAFFOLD.
//
// The OS-facing half: it hosts the SwiftUI unlock/picker and hands back an
// ASPasswordCredential. All the vault work lives in AutoFillModel, and all the
// crypto in the Rust core behind VaultSession, so this file is containment and
// nothing else.
//
// This is the part of iOS that was designed for third-party password managers,
// unlike the macOS equivalent the project shelved — no fight with Apple's own
// password menu, no Touch ID on every fill by decree. The cost here is different
// and self-inflicted: no device key exists on iOS, so every fill asks for the
// master password.

import AuthenticationServices
import SwiftUI
import UIKit
import os

private let log = Logger(subsystem: "no.sybr.vault.ios.autofill", category: "provider")

final class CredentialProviderViewController: ASCredentialProviderViewController {

    private var hosted: UIHostingController<UnlockPickerView>?

    // MARK: Quick fill (no UI)

    override func provideCredentialWithoutUserInteraction(for credentialRequest: ASCredentialRequest) {
        // Opening the vault needs the master password, which is user interaction
        // by definition — so ask the OS for the UI path rather than fail.
        log.info("provideWithoutUI -> userInteractionRequired")
        cancel(.userInteractionRequired)
    }

    // MARK: UI paths

    override func prepareInterfaceToProvideCredential(for credentialRequest: ASCredentialRequest) {
        guard credentialRequest.type == .password,
              let identity = credentialRequest.credentialIdentity as? ASPasswordCredentialIdentity,
              let recordID = identity.recordIdentifier
        else {
            cancel(.credentialIdentityNotFound)
            return
        }
        present(
            domains: [],
            direct: AutoFillModel.DirectRequest(recordID: recordID, user: identity.user))
    }

    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        present(
            domains: Set(serviceIdentifiers.map { $0.identifier.lowercased() }),
            direct: nil)
    }

    // MARK: Containment

    private func present(domains: Set<String>, direct: AutoFillModel.DirectRequest?) {
        let model = AutoFillModel(
            domains: domains,
            direct: direct,
            onFill: { [weak self] credential in
                self?.extensionContext.completeRequest(withSelectedCredential: credential)
            },
            onCancel: { [weak self] in self?.cancel(.userCanceled) })

        let root = UnlockPickerView(model: model)
        if let hosted {
            hosted.rootView = root
            return
        }

        let host = UIHostingController(rootView: root)
        hosted = host
        addChild(host)
        host.view.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(host.view)
        NSLayoutConstraint.activate([
            host.view.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            host.view.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            host.view.topAnchor.constraint(equalTo: view.topAnchor),
            host.view.bottomAnchor.constraint(equalTo: view.bottomAnchor),
        ])
        // UIKit containment is only complete once the child is told. Skipping it
        // is the classic cause of a child that never receives appearance
        // callbacks — which here would mean the password field never focuses.
        host.didMove(toParent: self)
    }

    private func cancel(_ code: ASExtensionError.Code) {
        extensionContext.cancelRequest(withError: ASExtensionError(code))
    }
}
