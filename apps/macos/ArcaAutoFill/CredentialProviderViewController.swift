// Arca — macOS AutoFill Credential Provider (passwords), M2 real vault.
//
// Fills the user's ACTUAL passwords: opens the shared vault via the Rust FFI
// (Touch ID reads the device key from the shared keychain), then returns the
// selected credential. The password is copied straight into ASPasswordCredential
// and never retained. Reading the key is user interaction, so the quick-fill
// (no-UI) entry point defers to the UI entry point where the Touch ID prompt is
// expected.

import AuthenticationServices
import SwiftUI
import os

private let log = Logger(subsystem: "no.sybr.vault.autofill", category: "provider")

final class CredentialProviderViewController: ASCredentialProviderViewController {

    // MARK: Quick fill (no UI)

    // We must prompt Touch ID to read the vault key, which counts as user
    // interaction — so ask the OS to show our UI path instead of filling silently.
    override func provideCredentialWithoutUserInteraction(for credentialRequest: ASCredentialRequest) {
        log.info("provideWithoutUI -> userInteractionRequired")
        extensionContext.cancelRequest(
            withError: ASExtensionError(.userInteractionRequired))
    }

    // MARK: UI path (Touch ID happens here)

    override func prepareInterfaceToProvideCredential(for credentialRequest: ASCredentialRequest) {
        guard credentialRequest.type == .password,
              let identity = credentialRequest.credentialIdentity as? ASPasswordCredentialIdentity,
              let recordID = identity.recordIdentifier
        else {
            extensionContext.cancelRequest(
                withError: ASExtensionError(.credentialIdentityNotFound))
            return
        }
        fill(recordID: recordID, user: identity.user)
    }

    // The user opened the AutoFill list manually: show matching logins.
    override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        let domains = Set(serviceIdentifiers.map { $0.identifier.lowercased() })
        Task { await presentList(matching: domains) }
    }

    // MARK: Helpers

    private func fill(recordID: String, user: String) {
        Task {
            do {
                let vault = try OpenVault.open() // Touch ID
                let password = try vault.password(forId: recordID)
                let credential = ASPasswordCredential(user: user, password: password)
                await MainActor.run {
                    self.extensionContext.completeRequest(withSelectedCredential: credential)
                }
            } catch {
                log.error("fill failed: \(String(describing: error), privacy: .public)")
                await MainActor.run {
                    self.extensionContext.cancelRequest(
                        withError: ASExtensionError(.userCanceled))
                }
            }
        }
    }

    @MainActor
    private func presentList(matching domains: Set<String>) async {
        var rows: [CredentialRow] = []
        var openError = false
        do {
            let vault = try OpenVault.open() // Touch ID
            let ids = try vault.identities()
            rows = ids
                .filter { domains.isEmpty || domains.contains($0.domain) }
                .map { CredentialRow(id: $0.id, user: $0.user, domain: $0.domain) }
        } catch {
            openError = true
            log.error("list open failed: \(String(describing: error), privacy: .public)")
        }

        let view = CredentialListView(
            rows: rows,
            errored: openError,
            onPick: { [weak self] row in self?.fill(recordID: row.id, user: row.user) },
            onCancel: { [weak self] in
                self?.extensionContext.cancelRequest(withError: ASExtensionError(.userCanceled))
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
