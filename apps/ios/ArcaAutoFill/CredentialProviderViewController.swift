// Arca — iOS AutoFill Credential Provider (passwords). SCAFFOLD.
//
// The OS-facing half: it hosts the SwiftUI unlock/picker and hands back an
// ASPasswordCredential. All the vault work lives in AutoFillModel, and all the
// crypto in the Rust core behind VaultSession, so this file is containment and
// nothing else.
//
// This is the part of iOS that was designed for third-party password managers,
// unlike the macOS equivalent the project shelved — no fight with Apple's own
// password menu, no Touch ID on every fill by decree. With quick unlock turned
// on, a fill is a biometric and a symmetric unwrap; without it, the master
// password and a full Argon2id derivation, in a keyboard accessory view.

import AuthenticationServices
import SwiftUI
import UIKit
import os

private let log = Logger(subsystem: "no.sybr.vault.ios.autofill", category: "provider")

final class CredentialProviderViewController: ASCredentialProviderViewController {

    private var hosted: UIHostingController<UnlockPickerView>?

    // MARK: Quick fill (no UI)

    override func provideCredentialWithoutUserInteraction(for credentialRequest: ASCredentialRequest) {
        // Opening the vault needs either a biometric (to read the device key) or
        // the master password. Both are user interaction by definition, so ask
        // the OS for the UI path rather than fail here.
        log.info("provideWithoutUI -> userInteractionRequired")
        cancel(.userInteractionRequired)
    }

    // MARK: Strong-password suggestion (no UI, no unlock)

    /// "Use Strong Password" on any sign-up field, system-wide.
    ///
    /// This is the one AutoFill entry point that answers instantly. Everything
    /// else here needs the vault open, which needs a biometric or the master
    /// password; generating needs neither, because nothing is read. So no
    /// `userInteractionRequired`, no sheet, no launch cost — the suggestion is
    /// simply there, the way Keychain's is.
    ///
    /// The rules matter. A site that caps at 16 characters or forbids symbols
    /// will reject a generated password, and a suggestion that gets rejected
    /// teaches people the feature is broken. `passwordRulesFromQuirks` is
    /// Apple's own correction for sites whose declared rules are wrong or
    /// missing, so it wins when present.
    @available(iOS 26.2, *)
    override func performWithoutUserInteraction(
        generatePasswordsRequest request: ASGeneratePasswordsRequest
    ) {
        let rules = request.passwordRulesFromQuirks
            ?? request.passwordFieldPasswordRules
            ?? request.confirmPasswordFieldPasswordRules
            ?? ""

        do {
            var results: [ASGeneratedPassword] = [
                ASGeneratedPassword(kind: .strong, value:
                    try VaultShared.generatePassword(rules: rules))
            ]
            // A second, letters-and-digits option. Sites reject symbols far
            // more often than they admit to in their rules, and the fallback
            // is otherwise for the user to invent one.
            let alphanumeric = try VaultShared.generatePassword(
                rules: rules.isEmpty
                    ? "allowed: lower, upper, digit;"
                    : rules + "; allowed: lower, upper, digit;")
            if alphanumeric != results[0].value {
                results.append(ASGeneratedPassword(kind: .alphanumeric, value: alphanumeric))
            }
            log.info("generate -> \(results.count, privacy: .public) suggestion(s)")
            extensionContext.completeGeneratePasswordRequest(results: results)
        } catch {
            // Cancelled rather than answered with something weak. The system
            // falls back to its own suggestion, which is a fine outcome; a
            // password from a library we could not call is not.
            log.error("generate failed: \(String(describing: error), privacy: .public)")
            cancel(.failed)
        }
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
