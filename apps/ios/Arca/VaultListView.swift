// The unlocked vault: search, pick, look at one login.
//
// Logins only. `vault_ffi_identities` filters to ItemKind::Login, so passkeys,
// SSH keys, Wi-Fi networks and secure notes are simply not visible from here —
// the ABI has no way to ask for them.

import SwiftUI

struct VaultListView: View {
    @Environment(VaultStore.self) private var store
    @State private var selected: VaultIdentity?

    var body: some View {
        @Bindable var store = store

        NavigationStack {
            Group {
                if store.identities.isEmpty {
                    ContentUnavailableView(
                        "No logins",
                        systemImage: "key",
                        description: Text("This vault has no login items."))
                } else if store.results.isEmpty {
                    ContentUnavailableView.search(text: store.query)
                } else {
                    List(store.results) { identity in
                        Button { selected = identity } label: { row(identity) }
                            .buttonStyle(.plain)
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
            }
            .sheet(item: $selected) { ItemDetailView(identity: $0) }
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
