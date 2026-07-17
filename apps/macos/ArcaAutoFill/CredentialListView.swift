// The extension's minimal picker UI (M1). Shows the one test credential; picking
// it completes the AutoFill request. In M2 this becomes the unlock screen +
// the real per-site credential list.

import SwiftUI

struct CredentialListView: View {
    let user: String
    let domain: String
    let onPick: () -> Void
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

            Text("Passwords for \(domain)")
                .font(.subheadline)
                .foregroundStyle(.secondary)

            Button(action: onPick) {
                HStack(spacing: 10) {
                    Image(systemName: "person.crop.circle")
                        .font(.title3)
                        .foregroundStyle(.secondary)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(user).font(.body)
                        Text(domain).font(.caption).foregroundStyle(.secondary)
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

            Spacer(minLength: 0)
        }
        .padding(16)
        .frame(minWidth: 320, minHeight: 200)
    }
}
