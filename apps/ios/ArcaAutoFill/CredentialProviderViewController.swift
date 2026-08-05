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
        switch credentialRequest {
        case let request as ASPasskeyCredentialRequest:
            guard let identity = request.credentialIdentity as? ASPasskeyCredentialIdentity,
                  let recordID = identity.recordIdentifier
            else {
                cancel(.credentialIdentityNotFound)
                return
            }
            present(
                domains: [],
                direct: .passkey(
                    recordID: recordID,
                    clientDataHash: request.clientDataHash,
                    rpID: identity.relyingPartyIdentifier))
        default:
            guard credentialRequest.type == .password,
                  let identity = credentialRequest.credentialIdentity as? ASPasswordCredentialIdentity,
                  let recordID = identity.recordIdentifier
            else {
                cancel(.credentialIdentityNotFound)
                return
            }
            present(
                domains: [],
                direct: .password(recordID: recordID, user: identity.user))
        }
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
            onFillPasskey: { [weak self] assertion in
                self?.extensionContext.completeAssertionRequest(using: assertion)
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

    // MARK: Entry points Arca cannot service

    // EVERY entry point this class does not override inherits Apple's default,
    // and that default DOES NOTHING. It does not complete the request and it
    // does not cancel it — the OS presents this view controller, the sheet
    // slides halfway up showing an empty white view, and it stays there. From
    // the outside the app has frozen; in fact it is waiting for a reply nobody
    // will ever send.
    //
    // That is what a user hit: scanning a code with the Camera app, choosing
    // Arca from the system's list of credential providers, and getting a blank
    // half-screen. Which method the OS invoked is not the point — the point is
    // that this class declared it could be a credential provider and then left
    // whole doors unanswered.
    //
    // So every remaining door is answered here. Where Arca genuinely cannot do
    // the job, it says so and the sheet goes away, which is a bad outcome the
    // user can act on rather than a hang they cannot.

    /// The user picked Arca from a system configuration flow.
    ///
    /// Nothing to configure in a sheet — the vault lives in the app — but this
    /// MUST complete or the sheet hangs, and completing is what dismisses it.
    override func prepareInterfaceForExtensionConfiguration() {
        log.info("extension configuration requested; completing")
        extensionContext.completeExtensionConfigurationRequest()
    }

    /// The door the system knocks on FIRST when a site offers to save a passkey.
    ///
    /// iOS 18 tries the no-UI path before presenting anything. Leaving it
    /// unanswered is why "save passkey -> choose Arca" still hung after the
    /// UI-side registration entry point was answered: the request never got
    /// that far. One door was fixed and the one in front of it was not.
    ///
    /// Refused outright rather than with `.userInteractionRequired`. Asking the
    /// system to present UI only to decline in the next breath costs the user a
    /// sheet to dismiss and tells them nothing extra — registration is not
    /// implemented here at all, so say so now and let the system fall back to
    /// its own passkey handling.
    @available(iOS 18.0, *)
    override func performWithoutUserInteractionIfPossible(
        passkeyRegistration registrationRequest: ASPasskeyCredentialRequest
    ) {
        log.error("no-UI passkey registration is not implemented in this extension")
        cancel(.failed)
    }

    /// Registering a new passkey from the system UI. Arca stores passkeys, but
    /// this extension has no registration path yet, and the browser extension
    /// is the route on every platform today.
    override func prepareInterface(forPasskeyRegistration registrationRequest: ASCredentialRequest) {
        log.error("passkey registration is not implemented in this extension")
        cancel(.failed)
    }

    /// One-time codes. `ProvidesOneTimeCodes` is NOT declared in Info.plist, so
    /// the OS should never ask — but "should never" is exactly the assumption
    /// that leaves a sheet hanging when it turns out to be wrong.
    @available(iOS 18.0, *)
    override func prepareOneTimeCodeCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
        log.error("one-time code list requested but not supported")
        cancel(.failed)
    }

    /// Text insertion, iOS 18+. Not declared either, and answered for the same
    /// reason.
    @available(iOS 18.0, *)
    override func prepareInterfaceForUserChoosingTextToInsert() {
        log.error("text insertion requested but not supported")
        cancel(.failed)
    }

    private func cancel(_ code: ASExtensionError.Code) {
        extensionContext.cancelRequest(withError: ASExtensionError(code))
    }
}
