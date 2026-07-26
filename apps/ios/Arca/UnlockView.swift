// Master-password unlock.
//
// There is no Face ID path, and that is a missing FFI export rather than an
// oversight: quick unlock needs a 32-byte device key minted into the keychain,
// and `vault-ffi` has no way to create one — `enable_device_unlock` exists in
// vault-core but is not exported, and using it would mean writing the vault file
// back, which the read-only ABI cannot do either. See ../README.md.
//
// So every unlock runs Argon2id with the vault header's parameters. That is
// deliberately expensive, which is why the button shows progress rather than
// pretending to be instant.

import SwiftUI

struct UnlockView: View {
    @Environment(VaultStore.self) private var store

    @State private var password = ""
    @FocusState private var focused: Bool

    private var isUnlocking: Bool { store.phase == .unlocking }

    var body: some View {
        VStack(spacing: 20) {
            Spacer()

            Image(systemName: "lock.fill")
                .font(.system(size: 44))
                .foregroundStyle(.tint)
            Text("Arca")
                .font(.largeTitle.bold())

            SecureField("Master password", text: $password)
                .textFieldStyle(.roundedBorder)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .submitLabel(.go)
                .focused($focused)
                .onSubmit(submit)
                .disabled(isUnlocking)

            if let failure = store.failure {
                Text(failure)
                    .font(.callout)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
            }

            Button(action: submit) {
                if isUnlocking {
                    ProgressView().frame(maxWidth: .infinity)
                } else {
                    Text("Unlock").frame(maxWidth: .infinity)
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(password.isEmpty || isUnlocking)

            Text("Deriving the key takes a moment — that is Argon2id doing its job.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            ImportVaultButton(title: "Import a different vault")
                .font(.caption)

            Spacer()
        }
        .padding(28)
        .onAppear { focused = true }
    }

    private func submit() {
        guard !password.isEmpty, !isUnlocking else { return }
        Task {
            await store.unlock(password: password)
            // Cleared either way. A wrong password is worth retyping; leaving it
            // in a live @State String is not worth the convenience.
            password = ""
        }
    }
}
