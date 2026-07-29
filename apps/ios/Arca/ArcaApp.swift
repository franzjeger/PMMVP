// Arca for iOS — SCAFFOLD.
//
// A viewer over the same Rust core the desktop uses, plus the AutoFill
// extension embedded alongside it. What it cannot do yet, and why, is in
// ../README.md — the short version is that the FFI is read-only and there is no
// sync, so the vault arrives by hand and leaves unchanged.

import SwiftUI

@main
struct ArcaApp: App {
    @State private var store = VaultStore()
    @State private var island = TotpActivityController()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(store)
                .environment(island)
                // iOS screenshots the window on the way to the app switcher and
                // writes that snapshot to disk. Cover it while inactive so a
                // list of sites and usernames is never the thing photographed.
                .overlay {
                    if scenePhase != .active { PrivacyCover() }
                }
                .onChange(of: scenePhase) { _, phase in
                    // Backgrounded means gone. The desktop app locks on window
                    // blur for the same reason: a suspended process holding a
                    // decrypted vault is a worse trade than retyping.
                    if phase == .background {
                        store.lock()
                    }
                    // The Live Activity deliberately SURVIVES that lock.
                    //
                    // It used to be stopped here, on the reasoning that a code
                    // taken from the vault must not outlive the vault being
                    // sealed. That sounds principled and made the feature
                    // impossible: iOS never shows an app's own activity while
                    // that app is in front, so the only moment it could appear
                    // was the moment this killed it.
                    //
                    // It also protected nothing. The digits are redacted by
                    // `.privacySensitive()` on a locked device, the code dies
                    // within thirty seconds, and anyone holding the phone
                    // unlocked can simply open Arca.
                    //
                    // Coming BACK is where it ends: you are in the app again,
                    // the code is on screen, and the island is noise.
                    if phase == .active {
                        island.stop()
                    }
                }
        }
    }
}

struct RootView: View {
    @Environment(VaultStore.self) private var store

    var body: some View {
        Group {
            switch store.phase {
            case .needsVault:
                ImportVaultView()
            case .locked, .unlocking:
                UnlockView()
            case .unlocked:
                VaultListView()
            }
        }
        // A vault can appear while the app is running — imported here, or
        // replaced from Files by something else.
        .onAppear { store.refresh() }
    }
}

private struct PrivacyCover: View {
    var body: some View {
        ZStack {
            Rectangle().fill(.background)
            Image(systemName: "lock.fill")
                .font(.system(size: 44))
                .foregroundStyle(.tint)
        }
        .ignoresSafeArea()
    }
}
