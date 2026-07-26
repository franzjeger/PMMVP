// One login. Metadata came with the list; the password is fetched on demand and
// lives in `@State` only while this sheet is on screen.

import SwiftUI

struct ItemDetailView: View {
    let identity: VaultIdentity

    @Environment(VaultStore.self) private var store
    @Environment(\.dismiss) private var dismiss

    @State private var revealed: String?
    @State private var busy = false
    @State private var copied = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    LabeledContent("Username", value: identity.user.isEmpty ? "—" : identity.user)
                    LabeledContent("Site", value: identity.domain)
                    if !identity.label.isEmpty {
                        LabeledContent("Title", value: identity.label)
                    }
                }

                Section("Password") {
                    if let revealed {
                        Text(revealed)
                            .font(.body.monospaced())
                            .textSelection(.enabled)
                            // Honoured wherever SwiftUI applies privacy
                            // redaction. The app-switcher snapshot is covered
                            // separately, in ArcaApp.
                            .privacySensitive()
                    } else {
                        Text("••••••••••••")
                            .font(.body.monospaced())
                            .foregroundStyle(.secondary)
                    }

                    Button(
                        revealed == nil ? "Reveal" : "Hide",
                        systemImage: revealed == nil ? "eye" : "eye.slash"
                    ) {
                        Task { await toggleReveal() }
                    }
                    .disabled(busy)

                    Button("Copy password", systemImage: "doc.on.doc") {
                        Task { await copy() }
                    }
                    .disabled(busy)
                }

                if copied {
                    Section {
                        Label(
                            "Copied. iOS clears the pasteboard in \(Int(SecretPasteboard.lifetime)) seconds.",
                            systemImage: "clock")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }

                if let failure = store.failure {
                    Section {
                        Text(failure).font(.callout).foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle(VaultListView.title(for: identity))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Done") { dismiss() }
                }
            }
        }
        .onDisappear { revealed = nil }
    }

    private func toggleReveal() async {
        if revealed != nil {
            revealed = nil
            return
        }
        busy = true
        defer { busy = false }
        revealed = await store.password(for: identity)
    }

    private func copy() async {
        busy = true
        defer { busy = false }

        // Fetched fresh when it isn't already on screen, so copying works
        // whether or not the password has been revealed.
        let password: String?
        if let revealed {
            password = revealed
        } else {
            password = await store.password(for: identity)
        }
        guard let password else { return }

        SecretPasteboard.copy(password)
        copied = true
    }
}
