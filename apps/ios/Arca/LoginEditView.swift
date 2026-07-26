// Add or edit a login on the phone.
//
// This is what turns the app from a viewer into a manager: until the FFI could
// write (ABI v6) you could read a password here but had to reach for the Mac to
// save one.
//
// Editing loads the existing password on appear, which costs one authenticated
// read — the identity list carries metadata only, never the secret. A create
// skips that entirely.

import SwiftUI

struct LoginEditView: View {
    /// nil creates a new login; otherwise the item being edited.
    let existing: VaultIdentity?

    @Environment(VaultStore.self) private var store
    @Environment(\.dismiss) private var dismiss

    @State private var title = ""
    @State private var username = ""
    @State private var password = ""
    @State private var url = ""
    @State private var revealed = false
    @State private var loading = false
    @State private var saving = false
    @State private var failure: String?

    private var isEdit: Bool { existing != nil }
    /// A login with nothing to identify it and nothing to fill is not worth
    /// saving; anything else is the user's call, not ours.
    private var canSave: Bool {
        !saving && !loading
            && !(title.isEmpty && username.isEmpty && url.isEmpty)
            && !password.isEmpty
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Title", text: $title)
                        .textContentType(.organizationName)
                    TextField("Website", text: $url)
                        .textContentType(.URL)
                        .keyboardType(.URL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }
                Section {
                    TextField("Username", text: $username)
                        .textContentType(.username)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    HStack {
                        // A password field the user cannot read back is a good
                        // way to save a typo they can never diagnose.
                        Group {
                            if revealed {
                                TextField("Password", text: $password)
                            } else {
                                SecureField("Password", text: $password)
                            }
                        }
                        .textContentType(.password)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()

                        Button {
                            revealed.toggle()
                        } label: {
                            Image(systemName: revealed ? "eye.slash" : "eye")
                        }
                        .buttonStyle(.borderless)
                        .accessibilityLabel(revealed ? "Hide password" : "Show password")
                    }
                }
                if let failure {
                    Section {
                        Text(failure)
                            .font(.footnote)
                            .foregroundStyle(.red)
                    }
                }
            }
            .disabled(loading)
            .navigationTitle(isEdit ? "Edit Login" : "New Login")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(saving ? "Saving…" : "Save") { Task { await save() } }
                        .disabled(!canSave)
                }
            }
            .task { await load() }
        }
    }

    /// Prefill from the item being edited. The password is fetched separately
    /// because the identity list deliberately carries no secrets.
    private func load() async {
        guard let existing else { return }
        title = existing.label
        username = existing.user
        url = existing.domain
        loading = true
        defer { loading = false }
        if let secret = await store.password(for: existing) {
            password = secret
        } else {
            // Saving now would overwrite the real password with an empty one.
            failure = "Could not read the current password. Close and try again."
        }
    }

    private func save() async {
        saving = true
        defer { saving = false }
        if let message = await store.saveLogin(
            id: existing?.id, title: title, username: username,
            password: password, url: url)
        {
            failure = message
            return
        }
        dismiss()
    }
}
