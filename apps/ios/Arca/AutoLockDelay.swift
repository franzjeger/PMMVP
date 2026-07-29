// How long the vault stays open while Arca is in the background.
//
// The old behaviour was "immediately", which reads as the safe default and is
// not. Locking on every app switch means a Face ID prompt to copy a password, a
// second one after pasting it, and a third when you come back for the code —
// and a protection people work around is not protecting anything.
//
// Apple Passwords behaves this way too: the vault stays open for a while after
// you leave, and the device passcode is the outer gate.

import Foundation

enum AutoLockDelay: String, CaseIterable, Identifiable {
    case immediately
    case oneMinute
    case fiveMinutes
    case fifteenMinutes
    case oneHour
    case never

    /// Five minutes: long enough to switch to Safari, paste, and come back
    /// twice; short enough that a phone left on a table re-locks before anyone
    /// wanders past. Not "never", which would make the choice for the user.
    static let `default` = AutoLockDelay.fiveMinutes

    init(stored: String?) {
        self = stored.flatMap(AutoLockDelay.init(rawValue:)) ?? .default
    }

    var id: String { rawValue }

    /// nil means never lock on time alone.
    var seconds: TimeInterval? {
        switch self {
        case .immediately: return 0
        case .oneMinute: return 60
        case .fiveMinutes: return 5 * 60
        case .fifteenMinutes: return 15 * 60
        case .oneHour: return 60 * 60
        case .never: return nil
        }
    }

    var label: String {
        switch self {
        case .immediately: return "Immediately"
        case .oneMinute: return "After 1 minute"
        case .fiveMinutes: return "After 5 minutes"
        case .fifteenMinutes: return "After 15 minutes"
        case .oneHour: return "After 1 hour"
        // Named for what it costs, not just what it does. "Never" alone reads
        // as a convenience setting rather than a decision about the vault.
        case .never: return "Only when I lock it"
        }
    }
}
