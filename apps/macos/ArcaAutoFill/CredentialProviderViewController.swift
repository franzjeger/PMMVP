// Arca — macOS AutoFill Credential Provider (passwords), M1 skeleton.
//
// Serves ONE hardcoded test credential so we can prove the OS integration end
// to end before wiring the real vault (M2). No real secret, no vault/FFI.
//
// Every entry point is logged (subsystem no.sybr.vault.autofill) and completes
// directly with the test credential — no match-guard that could silently drop
// the fill, and both the modern (ASCredentialRequest) and legacy
// (ASPasswordCredentialIdentity) shapes are covered so it works regardless of
// which one this macOS calls.

import AuthenticationServices
import SwiftUI
import os

private let log = Logger(subsystem: "no.sybr.vault.autofill", category: "provider")

enum M1Credential {
    static let recordID = "arca-m1-test"
    static let domain = "example.com"
    static let user = "arca-test"
    // NOT a real secret: a fixed placeholder so M1 can demonstrate a fill.
    static let password = "arca-m1-demo"
}

final class CredentialProviderViewController: ASCredentialProviderViewController {

    // MARK: Quick fill (no UI) — modern + legacy

    override func provideCredentialWithoutUserInteraction(for credentialRequest: ASCredentialRequest) {
        log.info("provideWithoutUI(request) type=\(credentialRequest.type.rawValue, privacy: .public) rec=\(credentialRequest.credentialIdentity.recordIdentifier ?? "nil", privacy: .public)")
        complete()
    }

    @available(macOS, deprecated: 14.0)
    override func provideCredentialWithoutUserInteraction(for credentialIdentity: ASPasswordCredentialIdentity) {
        log.info("provideWithoutUI(identity) rec=\(credentialIdentity.recordIdentifier ?? "nil", privacy: .public)")
        complete()
    }

    // MARK: UI paths — modern + legacy. Complete directly (nothing to unlock in M1).

    override func prepareInterfaceToProvideCredential(for credentialRequest: ASCredentialRequest) {
        log.info("prepareInterface(request) rec=\(credentialRequest.credentialIdentity.recordIdentifier ?? "nil", privacy: .public)")
        complete()
    }

    @available(macOS, deprecated: 14.0)
    override func prepareInterfaceToProvideCredential(for credentialIdentity: ASPasswordCredentialIdentity) {
        log.info("prepareInterface(identity) rec=\(credentialIdentity.recordIdentifier ?? "nil", privacy: .public)")
        complete()
    }

    // The user opened the AutoFill list manually.
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        log.info("prepareCredentialList count=\(serviceIdentifiers.count, privacy: .public)")
        presentList()
    }

    // MARK: Helpers

    private func complete() {
        let credential = ASPasswordCredential(
            user: M1Credential.user, password: M1Credential.password)
        log.info("completing with user=\(M1Credential.user, privacy: .public)")
        extensionContext.completeRequest(withSelectedCredential: credential, completionHandler: nil)
    }

    private func presentList() {
        let view = CredentialListView(
            user: M1Credential.user,
            domain: M1Credential.domain,
            onPick: { [weak self] in self?.complete() },
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
}
