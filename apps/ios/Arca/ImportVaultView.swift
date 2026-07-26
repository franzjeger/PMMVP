// Getting a vault onto the phone.
//
// This screen exists because sync does not. `apps/desktop/src-tauri/src/sync.rs`
// is a Google Drive client living inside the desktop app crate, so nothing else
// can call it; until it moves to a shared crate and grows an iOS OAuth flow
// (docs/IOS.md), the only way the file reaches the phone is the user carrying it
// there. AirDrop it from the Mac, then pick it here.

import SwiftUI
import UniformTypeIdentifiers

struct ImportVaultView: View {
    @Environment(VaultStore.self) private var store

    var body: some View {
        VStack(spacing: 20) {
            Spacer()
            Image(systemName: "tray.and.arrow.down")
                .font(.system(size: 44))
                .foregroundStyle(.tint)
            Text("No vault yet")
                .font(.title2.bold())
            Text("Arca has no sync on iOS yet. AirDrop `default.vault` from your Mac, then import it here.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            ImportVaultButton(title: "Import a vault file")
                .buttonStyle(.borderedProminent)

            if let failure = store.failure {
                Text(failure)
                    .font(.callout)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
            }
            Spacer()
        }
        .padding(28)
    }
}

/// Shared by the import screen and the unlock screen, so a vault can be replaced
/// without first deleting the one already there.
struct ImportVaultButton: View {
    let title: String

    @Environment(VaultStore.self) private var store
    @State private var picking = false

    var body: some View {
        Button(title, systemImage: "square.and.arrow.down") { picking = true }
            // `.data` rather than a custom type: `.vault` is not a registered
            // UTI, and a stricter filter would just hide the file the user came
            // to pick. The FFI is what actually decides whether it is a vault.
            .fileImporter(isPresented: $picking, allowedContentTypes: [.data]) { result in
                store.importVault(result)
            }
    }
}
