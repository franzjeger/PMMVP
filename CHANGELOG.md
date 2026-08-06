# Changelog

## Unreleased

### Bridge

- **The local bridge protocol is versioned.** It was a private arrangement
  between the app and its own native-messaging host, so an unversioned,
  undocumented wire format cost nothing. It stops being private as soon as
  something else opens the socket — a passkey client inside an Electron app
  cannot use native messaging, so it connects directly — and then a change here
  breaks something over there with no signal but "passkeys stopped working". The
  handshake now states a version in both directions and refuses a peer it was not
  written against. Both sides treat an absent version as v1, so an old host and a
  new app, or the reverse, still work.

### Passkeys

- **Signing in to Microsoft 365 works.** Two separate bugs stacked on top of
  each other, and both were invisible from inside Arca, which reported success
  either way.

  The first was the gesture check. Entra does not run the ceremony on the page
  you click: it navigates to `login.microsoft.com/common/bridge/fido`, and *that*
  page fires `get()` on load. The gesture was tracked inside the page, so it died
  with the page and every M365 sign-in fell through to the browser — on Linux
  into the QR / security-key dialog, because there is no platform authenticator
  to catch it quietly. The gesture now lives in a per-tab ledger that outlives
  the navigation, and is still spent once per ceremony.

  The second was the credential itself. Arca handed the site an object literal
  with the right fields but no `toJSON()` and the wrong prototype, so
  `instanceof PublicKeyCredential` was false. The ceremony completed, Arca said
  it had signed you in, and the site's own code threw while handling the answer.
  It is now a conforming credential.
- **Per-site control over passkeys**, in the extension popup: ask (the default),
  always, or never. `never` is the way to keep Arca out of a site whose page
  fires passkey probes you do not want. This only decides who answers a
  ceremony — the vault must still be unlocked and the app must still approve.
- **A refused registration says so.** When a site tried to register a passkey
  Arca already held for that account, Arca refused silently and the page said
  "you already have a passkey" — which is wrong whenever the *site* is the one
  that lost it, and left no hint that the way out is to delete Arca's copy
  first. Arca now tells you.
- Every ceremony Arca declines to answer logs why, at `console.debug`. A missing
  gesture, a locked vault, no passkey for the site and a per-site "never" were
  previously all the same silence.
- **Firefox gets passkeys at all.** The Firefox manifest shipped without the
  passkey content scripts, so the feature had never worked there. Adding them
  needs `world: "MAIN"`, which raises the minimum Firefox to 128.

## 0.3.0 — 2026-07-28

The first published release. Earlier versions existed only as builds on the
author's own machine, so there is nothing to upgrade *from* yet; auto-update
starts working from here.

### Data safety

- **A permanently deleted credential no longer comes back.** Emptying the Trash
  removed the item and left nothing behind, so the next sync with a device that
  still held it put it straight back — worst for exactly the password someone
  destroys on purpose. A hard delete now leaves a record (an id and a timestamp,
  nothing derived from the secret) that travels with the vault. An edit made
  *after* the deletion still wins, the same rule a soft delete already followed.
- **A vault written by a newer Arca is refused instead of overwritten.** An
  unreadable remote copy is treated as a half-finished upload and replaced,
  which is right for a torn file and catastrophic for one written by a version
  that knows more than this build does. Unknown-but-ours containers are now
  refused; genuinely foreign bytes are still replaced.
- The vault file format is now `SYBRVLT3`. Older files open unchanged and are
  upgraded on the next save. **Older builds cannot read the new file**, so this
  is one-way — the automatic snapshot taken before every save is the way back.

### Passkeys

- **The GitHub passkey prompt loop is fixed.** Declining used to silence a site
  for a flat 90 seconds and then ask again, forever. It now escalates — 90
  seconds, 15 minutes, an hour, then silent for that site for the rest of the
  session — and Arca says so rather than going quiet unexplained. A successful
  sign-in clears it; quitting Arca resets it.
- The browser extension no longer treats "the user clicked something in the last
  five seconds" as "the user asked for this passkey". It watches for real input
  itself, on a tighter window, and uses the gesture up: one click, one ceremony.

### iOS

- The iOS app can now **add, edit and delete logins**, not just read them
  (C ABI v6), and **syncs with Google Drive** using its own OAuth client. It
  runs in the simulator. No device has run it and no sign-in has completed from
  a phone yet — see [`docs/IOS.md`](./docs/IOS.md).

### Under the hood

- Auto-update is wired: this build can be replaced by the next one without
  reinstalling by hand.
- `vault-sync` is its own crate, so the phone and the desktop share one sync
  engine instead of the desktop hiding it.
- The Google OAuth client secret is no longer in the source. It is supplied at
  build time; a build without it works completely except that Drive sync
  refuses to connect, and says so. See [`docs/SYNC.md`](./docs/SYNC.md).

### Still true, and worth repeating

Arca has **not been independently audited**. Read [`SECURITY.md`](./SECURITY.md)
and [`THREAT_MODEL.md`](./THREAT_MODEL.md) before trusting it with real secrets.
