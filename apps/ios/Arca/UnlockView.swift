// Unlock: Face ID if a device key has been minted on this device, the master
// password otherwise.
//
// The biometric path is attempted once automatically. A password manager that
// makes you tap before it will even ask is one you stop using, and the password
// field stays right there for when it is declined or unavailable.
//
// The password path runs Argon2id with the vault header's parameters, which is
// deliberately expensive — hence progress rather than a button pretending to be
// instant. Quick unlock exists precisely to avoid paying that on every fill.

import SwiftUI

struct UnlockView: View {
    @Environment(VaultStore.self) private var store

    @State private var password = ""
    @State private var didTryBiometrics = false
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

            if store.quickUnlockAvailable {
                Button("Use Face ID", systemImage: "faceid") {
                    Task { await store.unlockWithDeviceKey() }
                }
                .disabled(isUnlocking)
            } else {
                Text("Deriving the key takes a moment — that is Argon2id doing its job.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }

            ImportVaultButton(title: "Import a different vault")
                .font(.caption)

            Spacer()
        }
        .padding(28)
        .task {
            // Once per appearance. Backgrounding locks the vault, which brings
            // this view back and legitimately re-arms the prompt; a failed or
            // declined attempt must not loop.
            //
            // `await` the probe rather than reading the cached flag: this runs
            // before the first refresh has landed, so the flag is still false
            // here and reading it would silently skip the whole thing — turning
            // an automatic unlock into a button. Face ID should happen because
            // you opened the app, not because you asked twice.
            if !didTryBiometrics, await store.resolveQuickUnlockAvailability() {
                didTryBiometrics = true
                await store.unlockWithDeviceKey()
            }
            focused = store.phase != .unlocked
        }
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
