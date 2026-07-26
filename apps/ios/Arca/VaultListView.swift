// The unlocked vault: search, pick, look at one login.
//
// Logins only. `vault_ffi_identities` filters to ItemKind::Login, so passkeys,
// SSH keys, Wi-Fi networks and secure notes are simply not visible from here —
// the ABI has no way to ask for them.

import SwiftUI

struct VaultListView: View {
    @Environment(VaultStore.self) private var store
    @State private var selected: VaultIdentity?
    @State private var editing: VaultIdentity?
    @State private var creating = false

    var body: some View {
        @Bindable var store = store

        NavigationStack {
            Group {
                if store.identities.isEmpty {
                    ContentUnavailableView {
                        Label("No logins", systemImage: "key")
                    } description: {
                        Text("This vault has no login items.")
                    } actions: {
                        Button("Add a login") { creating = true }
                    }
                } else if store.results.isEmpty {
                    ContentUnavailableView.search(text: store.query)
                } else {
                    List(store.results) { identity in
                        Button { selected = identity } label: { row(identity) }
                            .buttonStyle(.plain)
                            .swipeActions(edge: .trailing) {
                                Button("Delete", systemImage: "trash", role: .destructive) {
                                    Task { await store.deleteLogin(identity) }
                                }
                                Button("Edit", systemImage: "pencil") {
                                    editing = identity
                                }
                                .tint(.accentColor)
                            }
                    }
                    .listStyle(.plain)
                }
            }
            .navigationTitle("Logins")
            .searchable(text: $store.query, prompt: "Search logins")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Lock", systemImage: "lock") { store.lock() }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button("Add login", systemImage: "plus") { creating = true }
                }
                ToolbarItem(placement: .topBarLeading) {
                    Menu("Options", systemImage: "ellipsis.circle") {
                        if store.quickUnlockEnabled {
                            Button("Turn off quick unlock", systemImage: "faceid") {
                                Task { await store.disableQuickUnlock() }
                            }
                        } else {
                            Button("Unlock with Face ID next time", systemImage: "faceid") {
                                Task { await store.enableQuickUnlock() }
                            }
                        }
                    }
                }
            }
            .sheet(item: $selected) { ItemDetailView(identity: $0) }
            .sheet(item: $editing) { LoginEditView(existing: $0) }
            .sheet(isPresented: $creating) { LoginEditView(existing: nil) }
            // Only after an unlock has actually asked the store — `nil` means
            // we don't know yet, and guessing would nag people who are set up.
            .safeAreaInset(edge: .bottom) {
                VStack(spacing: 0) {
                    // A menu action that fails leaves no trace otherwise: the
                    // sheet is gone and the toggle simply did not move.
                    if let failure = store.failure { Banner(text: failure, bad: true) }
                    if store.autoFillEnabled == false { AutoFillHint() }
                }
            }
        }
    }

    private func row(_ identity: VaultIdentity) -> some View {
        HStack(spacing: 12) {
            Image(systemName: "person.crop.circle")
                .font(.title2)
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 2) {
                Text(Self.title(for: identity))
                Text(identity.domain)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Image(systemName: "chevron.right")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
        .contentShape(Rectangle())
    }

    /// The username, falling back to the item's title and then its domain — a
    /// login saved without a username shouldn't render as a blank row.
    static func title(for identity: VaultIdentity) -> String {
        [identity.user, identity.label].first { !$0.isEmpty } ?? identity.domain
    }
}

/// Shown when the identity store refused the publish because AutoFill is off.
/// No button: iOS has no public deep link to the AutoFill settings pane, and a
/// button that opened the wrong page would be worse than saying where to go.
private struct AutoFillHint: View {
    var body: some View {
        Banner(
            text: "Turn Arca on in Settings ▸ General ▸ AutoFill & Passwords to fill from the keyboard.",
            bad: false)
    }
}

private struct Banner: View {
    let text: String
    let bad: Bool

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: bad ? "exclamationmark.circle" : "exclamationmark.triangle")
                .foregroundStyle(bad ? .red : .orange)
            Text(text)
                .font(.footnote)
                .foregroundStyle(.secondary)
            Spacer(minLength: 0)
        }
        .padding(12)
        .frame(maxWidth: .infinity)
        .background(.thinMaterial)
    }
}
