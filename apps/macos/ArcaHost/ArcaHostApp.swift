// Arca AutoFill — dev host app (M1).
//
// This app exists to (a) contain the AutoFill Credential Provider extension so
// the OS discovers it, and (b) publish one HARDCODED test credential identity to
// ASCredentialIdentityStore so it shows up as an AutoFill suggestion. There is no
// vault access here yet — that is M2. The shipping container will be the Tauri
// Arca.app; this host is only a build/debug/registration harness.

import AuthenticationServices
import SwiftUI

// The single test identity M1 advertises. The record identifier is the stable id
// the extension matches on; the domain is chosen at runtime so you can point the
// demo at any login page (no real account involved — the password is a fixed
// placeholder). Must stay in sync with M1Credential in the extension.
enum TestIdentity {
    static let user = "arca-test"
    static let recordID = "arca-m1-test"

    static func credentialIdentity(domain: String) -> ASPasswordCredentialIdentity {
        ASPasswordCredentialIdentity(
            serviceIdentifier: ASCredentialServiceIdentifier(identifier: domain, type: .domain),
            user: user,
            recordIdentifier: recordID)
    }
}

@main
struct ArcaHostApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
        .windowResizability(.contentSize)
    }
}

struct ContentView: View {
    @State private var status: String = "Checking…"
    @State private var isEnabled = false
    @State private var domain = "example.com"

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Arca AutoFill — dev host")
                .font(.title2).bold()

            Text(status)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Divider()

            Text("M1 checklist")
                .font(.headline)
            VStack(alignment: .leading, spacing: 6) {
                Label("Build & run this app once (registers the extension).", systemImage: "1.circle")
                Label("System Settings ▸ General ▸ AutoFill & Passwords ▸ enable Arca.", systemImage: "2.circle")
                Label("Type a domain that has a login form, then Register.", systemImage: "3.circle")
                Label("Open that site in Safari and pick “\(TestIdentity.user)” in the username field.", systemImage: "4.circle")
            }
            .font(.callout)

            HStack {
                Text("Domain:")
                TextField("example.com", text: $domain)
                    .textFieldStyle(.roundedBorder)
                    .frame(width: 240)
            }
            .padding(.top, 2)

            HStack {
                Button("Open AutoFill Settings") { openAutoFillSettings() }
                Button("Register test identity") { register() }
                    .disabled(!isEnabled || domain.trimmingCharacters(in: .whitespaces).isEmpty)
                Spacer()
                Button("Refresh") { Task { await refresh() } }
            }
            .padding(.top, 4)
        }
        .padding(28)
        .frame(width: 500)
        .task { await refresh() }
    }

    // Reflect whether the OS has Arca enabled as an AutoFill provider.
    private func refresh() async {
        let state = await ASCredentialIdentityStore.shared.state()
        isEnabled = state.isEnabled
        status = state.isEnabled
            ? "Arca is enabled as an AutoFill provider. Register a domain, then try it in Safari."
            : "Arca is NOT enabled yet. Open AutoFill Settings, turn Arca on, then Refresh."
    }

    // Publish the one test identity for the chosen domain so it appears as an
    // AutoFill suggestion there.
    private func register() {
        let host = domain.trimmingCharacters(in: .whitespaces)
        ASCredentialIdentityStore.shared.saveCredentialIdentities(
            [TestIdentity.credentialIdentity(domain: host)]
        ) { success, error in
            Task { @MainActor in
                if success {
                    status = "Registered “\(TestIdentity.user)” for \(host). Open it in Safari and focus the login field."
                } else {
                    status = "Could not register the identity: \(error?.localizedDescription ?? "unknown error")."
                }
            }
        }
    }

    private func openAutoFillSettings() {
        // Best-effort deep link to the AutoFill & Passwords pane; if it does not
        // resolve, the checklist above gives the manual path.
        let candidates = [
            "x-apple.systempreferences:com.apple.Passwords-Settings.extension",
            "x-apple.systempreferences:com.apple.preferences.password",
        ]
        for s in candidates {
            if let url = URL(string: s), NSWorkspace.shared.open(url) { return }
        }
    }
}
