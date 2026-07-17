// The extension's picker UI: the real logins for the site, from the vault.
// Picking one fills it (after the Touch ID that opened the vault).

import SwiftUI

struct CredentialRow: Identifiable {
    let id: String
    let user: String
    let domain: String
}

struct CredentialListView: View {
    let rows: [CredentialRow]
    let errored: Bool
    let onPick: (CredentialRow) -> Void
    let onCancel: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Image(systemName: "key.fill").foregroundStyle(.tint)
                Text("Arca").font(.headline)
                Spacer()
                Button("Cancel", action: onCancel)
                    .buttonStyle(.plain)
                    .foregroundStyle(.secondary)
            }

            if errored {
                Text("Couldn't open your vault. Make sure Arca is set up and try again.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else if rows.isEmpty {
                Text("No matching logins.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else {
                ScrollView {
                    VStack(spacing: 6) {
                        ForEach(rows) { row in
                            Button { onPick(row) } label: {
                                HStack(spacing: 10) {
                                    Image(systemName: "person.crop.circle")
                                        .font(.title3)
                                        .foregroundStyle(.secondary)
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(row.user.isEmpty ? row.domain : row.user)
                                            .font(.body)
                                        Text(row.domain).font(.caption).foregroundStyle(.secondary)
                                    }
                                    Spacer()
                                    Image(systemName: "chevron.right")
                                        .font(.caption)
                                        .foregroundStyle(.tertiary)
                                }
                                .padding(10)
                                .background(.quaternary, in: RoundedRectangle(cornerRadius: 8))
                                .contentShape(Rectangle())
                            }
                            .buttonStyle(.plain)
                        }
                    }
                }
            }

            Spacer(minLength: 0)
        }
        .padding(16)
        .frame(minWidth: 340, minHeight: 240)
    }
}
