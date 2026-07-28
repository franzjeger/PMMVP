// The Live Activity: a verification code in the Dynamic Island and on the lock
// screen, so it can be read while you are in the app you need to paste it into.
//
// That is the whole point. A code you have to leave the browser to look up is a
// code you retype from memory and get wrong.
//
// PRIVACY: a lock screen is a public surface. Every view of the code carries
// `.privacySensitive()`, so iOS redacts the digits when the device is locked
// while leaving the countdown visible. A second factor readable without
// unlocking the phone is not a second factor.
//
// THE COUNTDOWN NEVER UPDATES. `Text(timerInterval:)` is rendered by the system
// from a date, so it keeps ticking with Arca closed, suspended, or killed. The
// alternative — pushing a new state every second — is not merely wasteful, it
// is impossible from a backgrounded app, which is exactly when this is useful.

import ActivityKit
import SwiftUI
import WidgetKit

@main
struct ArcaWidgetsBundle: WidgetBundle {
    var body: some Widget {
        TotpLiveActivity()
    }
}

struct TotpLiveActivity: Widget {
    var body: some WidgetConfiguration {
        ActivityConfiguration(for: TotpActivityAttributes.self) { context in
            LockScreenView(context: context)
                .activityBackgroundTint(Color.black.opacity(0.6))
                .activitySystemActionForegroundColor(.white)
        } dynamicIsland: { context in
            DynamicIsland {
                DynamicIslandExpandedRegion(.leading) {
                    Label(context.attributes.label, systemImage: "key.fill")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                DynamicIslandExpandedRegion(.trailing) {
                    CountdownText(to: context.state.expiresAt)
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(.secondary)
                }
                DynamicIslandExpandedRegion(.center) {
                    CodeText(state: context.state, size: .title)
                }
            } compactLeading: {
                Image(systemName: "key.fill").foregroundStyle(.tint)
            } compactTrailing: {
                // The compact trailing slot is a few characters wide, so it gets
                // the seconds rather than the code — enough to decide whether to
                // tap now or wait for the next one.
                CountdownText(to: context.state.expiresAt)
                    .font(.caption2.monospacedDigit())
                    .frame(width: 32)
            } minimal: {
                Image(systemName: "key.fill").foregroundStyle(.tint)
            }
        }
    }
}

/// Shown on the lock screen and in the banner.
private struct LockScreenView: View {
    let context: ActivityViewContext<TotpActivityAttributes>

    var body: some View {
        HStack(alignment: .center, spacing: 14) {
            Image(systemName: "key.fill")
                .font(.title2)
                .foregroundStyle(.tint)
            VStack(alignment: .leading, spacing: 2) {
                Text(context.attributes.label)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                CodeText(state: context.state, size: .title2)
            }
            Spacer()
            CountdownText(to: context.state.expiresAt)
                .font(.body.monospacedDigit())
                .foregroundStyle(.secondary)
        }
        .padding()
    }
}

/// The digits, or an honest replacement once they have expired.
///
/// After `expiresAt` the app may well be closed, so there is no new code to show
/// and no way to fetch one. Saying so beats leaving six stale digits on screen
/// that look current and are not.
private struct CodeText: View {
    let state: TotpActivityAttributes.ContentState
    let size: Font

    var body: some View {
        if Date() < state.expiresAt {
            Text(spaced(state.code))
                .font(size.monospaced().weight(.semibold))
                .privacySensitive()
        } else {
            Text("Open Arca")
                .font(.callout)
                .foregroundStyle(.secondary)
        }
    }

    /// "123 456" reads as two halves you can type; "123456" reads as one number.
    private func spaced(_ code: String) -> String {
        guard code.count == 6 else { return code }
        let mid = code.index(code.startIndex, offsetBy: 3)
        return "\(code[..<mid]) \(code[mid...])"
    }
}

/// A countdown the SYSTEM renders, so it stays right with Arca not running.
private struct CountdownText: View {
    let to: Date

    var body: some View {
        if Date() < to {
            Text(timerInterval: Date()...to, countsDown: true)
                .multilineTextAlignment(.trailing)
        } else {
            Text("—")
        }
    }
}
