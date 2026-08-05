# Passkeys (WebAuthn) — architecture & roadmap

**Status:** there are **three** ways an authenticator can reach a passkey
ceremony, and Arca ships one of them.

| Path | State |
| --- | --- |
| **Browser extension** (`extension/chromium/passkey.js`) | **Working**, on every Chromium browser and on Linux, where no platform authenticator exists at all. This is what signs you in today. |
| **OS credential provider** (`apps/macos/`, `apps/ios/`) | **Not built for passkeys.** `ProvidesPasskeys` is deliberately `false`, so Arca does not appear in the system chooser only to fail. Gated on an Apple Developer account. |
| **CTAP2 authenticator** (`crates/vault-ctap`, `crates/vault-uhid`, `app/ctap.rs`) | **Complete and wired to the vault; not yet run against a kernel.** Starts with the app on Linux, best-effort. See below. |

The cryptographic core underneath both is `crates/vault-core/src/passkey.rs`,
implemented and unit-tested.

## How the extension path works

Passwords autofill by typing text into a field, which any content script can do.
Passkeys go through the browser's **WebAuthn** engine
(`navigator.credentials.create/get`), so Arca wraps that API in the page's own
JS world — a `world: "MAIN"` content script at `document_start` — and answers the
ceremony itself via the isolated relay → background worker → native host →
loopback bridge. Anything it cannot service (vault locked, no passkey for this
relying party, a non-ES256 request) falls through to the browser's real handler,
so security keys and phones keep working. Every fallback logs its reason at
`console.debug`, because from the outside they are indistinguishable.

Two things about this path are easy to get wrong, and both shipped broken once:

- **Deciding whether the user asked for it.** A ceremony often does not run in
  the document the user clicked in — Microsoft Entra navigates to
  `login.microsoft.com/common/bridge/fido`, which fires `get()` on load. A
  gesture tracked inside the page dies with the page, so the gesture is kept in
  a per-tab ledger in the background worker, and consumed once. A per-site
  `ask`/`always`/`never` override lives in the popup.
- **What is handed back.** The relying party must receive something that behaves
  like a real `PublicKeyCredential` — `toJSON()` and working `instanceof` — not
  an object literal with the right fields. Get it wrong and the ceremony
  *succeeds*, Arca reports success, and the site fails on its own error.

`extension/test/passkey.test.mjs` covers both against the real files.

## The CTAP2 path (Linux)

The extension path solves one browser at a time. Every other WebAuthn client on
the machine — Firefox, an Electron app like teams-for-linux, `ssh-keygen -t
ecdsa-sk` — needs its own shim, written against its own injection quirks, and
`contextIsolation: false` makes some of them unsafe to write at all.

There is a way out that costs one implementation instead of N: **speak CTAP2**,
the protocol a hardware security key speaks. Every one of those clients already
talks it. Nothing has to know Arca exists.

Upstream, the `credentialsd` D-Bus portal from the Credentials for Linux project
is building the standards-track answer, but it mediates access to *external*
authenticators — USB, BLE, phone — and has no provider interface a password
manager can register through. The slot Arca wants does not exist yet. Presenting
as a security key does not need it to.

```
 ┌───────────────────────────────────────────────────────────────────┐
 │  Any WebAuthn client: Chromium, Firefox, Electron, ssh-keygen     │
 └───────────────┬───────────────────────────────────────────────────┘
                 │  CTAP2 over USB HID
                 ▼
 ┌───────────────────────────────────────────────────────────────────┐
 │  vault-uhid — the virtual device      [BUILT, KERNEL UNVERIFIED]  │
 │   • /dev/uhid event codec, FIDO report descriptor                 │
 │   • run loop: reader thread + authenticator thread + KEEPALIVE    │
 │   • needs a udev rule; see 70-arca-uhid.rules and the crate docs  │
 └───────────────┬───────────────────────────────────────────────────┘
                 │  64-byte HID reports
                 ▼
 ┌───────────────────────────────────────────────────────────────────┐
 │  vault-ctap::hid — CTAPHID framing              [DONE + TESTED]   │
 │   • initialisation/continuation packets, channels, reassembly     │
 │   • INIT/PING/CBOR/CANCEL, transaction atomicity, timeouts        │
 └───────────────┬───────────────────────────────────────────────────┘
                 │  command byte + CBOR
                 ▼
 ┌───────────────────────────────────────────────────────────────────┐
 │  vault-ctap                                     [DONE + TESTED]   │
 │   • getInfo / makeCredential / getAssertion / getNextAssertion    │
 │   • CTAP2 canonical CBOR, status codes, silent pre-flight         │
 │   • no I/O, no key material — a Backend trait is the only seam    │
 └───────────────┬───────────────────────────────────────────────────┘
                 │  Backend: discover / lookup / create / sign / confirm
                 ▼
 ┌───────────────────────────────────────────────────────────────────┐
 │  VaultAuthenticator — apps/desktop/src-tauri/src/ctap.rs  [DONE]  │
 │   • the same vault, the same prompt and decline cooldown, and     │
 │     the same passkey log as the extension path in bridge.rs       │
 │   • started from main.rs on Linux; best-effort, never fatal       │
 └───────────────────────────────────────────────────────────────────┘
```

Four decisions in `vault-ctap` worth knowing before extending it:

- **No CTAP PIN protocol.** `getInfo` reports `uv: true` and omits `clientPin`
  entirely, so platforms drive us with built-in user verification and Arca's
  master-password prompt *is* the verification. A website can never see, set, or
  brute-force a PIN belonging to the vault.
- **Silent assertions are answered without prompting.** `up: false, uv: false` is
  how browsers enumerate credentials before showing any UI; prompting there would
  mean a master-password dialog on every page that mentions WebAuthn. The
  signature comes back with UP and UV clear, and WebAuthn §7.2 requires the
  relying party to reject it — the same bargain every hardware key makes.
- **`authenticatorReset` is refused.** On a real key a reset wipes its
  credentials; here those are items in the user's vault, next to their passwords,
  and the command would be reachable by anything that can open the HID device.
- **What this path gives up.** The extension binds `rp_id` to a page origin the
  page cannot forge. A CTAP authenticator never sees an origin — only an rpId the
  *client* vouches for. Browsers do that check correctly; a malicious native
  process does not have to. The consent prompt must therefore show the rpId, and
  it is the user who is the phishing check.

Known gaps: no extensions (`hmac-secret`, `credProtect`, `credBlob`), no
credential management, and `authenticatorSelection` is answered even though we
advertise `FIDO_2_0` — a platform that asks gets a useful answer rather than an
error, and it contradicts nothing else we claim.

### Verifying the transport

Every layer above has unit tests, but nothing has yet been run against a real
kernel — the uhid codec is checked against transcribed struct offsets, not
against Linux's opinion of them. The first thing to do is prove the round trip:

```sh
cargo build -p vault-uhid --example smoke
sudo ./target/debug/examples/smoke     # /dev/uhid is root-only by default

# in another shell
fido2-token -L                         # does it appear as a FIDO device?
fido2-token -I /dev/hidrawN            # CTAPHID INIT + authenticatorGetInfo
```

`fido2-token -I` exercises the whole stack — device creation, hidraw, CTAPHID
framing, canonical CBOR — and prints back the versions, options and AAGUID from
`get_info`. If those match what `vault-ctap` claims, the transport is sound.

Then the real thing, which needs the app itself to reach `/dev/uhid`:

```sh
sudo install -m 644 crates/vault-uhid/70-arca-uhid.rules /etc/udev/rules.d/
sudo udevadm control --reload && sudo udevadm trigger
```

Restart Arca, unlock the vault, and register a passkey at
<https://webauthn.io> — the browser should offer "Arca Passkey Authenticator"
as a security key, and Arca should ask for the master password naming
`webauthn.io`. The passkey then appears in the vault like any other item, and
`passkey-requests.log` records the ceremony with origin `(ctap-hid)`.

Two things to watch for on that first run, because they are the ones that will
differ from the tests:

- **A prompt on page load with no ceremony behind it.** That would mean a silent
  pre-flight assertion is being treated as a real one. It should not be — the
  test suite covers it — but it is the failure that would make Arca unusable
  rather than merely broken.
- **The browser giving up after a few seconds.** That is `KEEPALIVE` not
  reaching the host, and it only shows up against a real one.

## What the OS credential provider would add

To appear in the system's "Choose where to save your passkey" chooser on macOS
and iOS (the way iCloud Keychain, 1Password and Dashlane do), an app must ship a
native **AutoFill Credential Provider** app extension that the OS loads and the
user enables in **System Settings → Passwords → Password Options**. That is a
different mechanism from both the loopback autofill bridge and the WebAuthn shim
above, and it is the only way to serve passkeys *outside* the browser.

## The pieces

```
 ┌───────────────────────────────────────────────────────────────────┐
 │  Relying party (github.com) in the browser                        │
 │     navigator.credentials.create()/get()                          │
 └───────────────┬───────────────────────────────────────────────────┘
                 │  WebAuthn, driven by the OS
                 ▼
 ┌───────────────────────────────────────────────────────────────────┐
 │  AutoFill Credential Provider extension (Swift)     [NOT BUILT]   │
 │  no passkey provider exists; apps/macos/ArcaAutoFill and          │
 │  apps/ios/ArcaAutoFill are passwords-only (ProvidesPasskeys=false)│
 │   • ASCredentialProviderExtension: prepare list / register /      │
 │     assert; the OS supplies clientDataHash + does Touch ID        │
 │   • reads the vault from the shared App Group container           │
 │   • calls the Rust core over a C ABI ↓                            │
 └───────────────┬───────────────────────────────────────────────────┘
                 │  C ABI
                 ▼
 ┌───────────────────────────────────────────────────────────────────┐
 │  vault-ffi (Rust staticlib/cdylib)              [DONE, ABI v3]    │
 │  crates/vault-ffi/  — thin C wrapper over…                        │
 └───────────────┬───────────────────────────────────────────────────┘
                 ▼
 ┌───────────────────────────────────────────────────────────────────┐
 │  vault-core::passkey (P-256 / ES256 WebAuthn)   [DONE + TESTED]   │
 │   • create()  → attestationObject (fmt "none") + private key      │
 │   • assert()  → authenticatorData + DER ES256 signature           │
 │  vault-core / vault-store — the encrypted vault the passkey lives │
 │  in, unlocked via the OS-keychain device key (Touch ID).          │
 └───────────────────────────────────────────────────────────────────┘
```

## What is done

- **`vault-core::passkey`** — ES256/P-256 authenticator: keypair generation,
  `authenticatorData` assembly, COSE public-key encoding, `attestationObject`
  (`fmt: "none"`) for registration, and DER ECDSA assertion signatures over
  `authenticatorData || clientDataHash`, plus the signature counter. Unit-tested
  (attestation shape, signature verifies against the credential's public key, a
  wrong key is rejected, bad key material errors instead of panicking).
- **`VaultItem::Passkey`** now stores the real credential (rp_id, user_name,
  user_handle, credential_id, private key, sign_count), zeroized like every
  secret and encrypted at rest. It round-trips through the vault's tagged-CBOR
  payload (test in `vault-core/src/lib.rs`).

## What remains (gated on an Apple Developer account)

1. **`vault-ffi`** — mostly there now. Vault open/unlock crosses the ABI (v2 with
   the device key, v3 with the master password), and
   `vault_ffi_passkey_create`/`_assert` expose the authenticator itself. What is
   missing is *listing* stored passkeys and *writing* a new one back, which needs
   the same vault-write surface iOS needs — see [`IOS.md`](./IOS.md) §2.
2. **Xcode wrapper** — solved. `apps/macos/project.yml` builds a host and embeds
   the `.appex`, and `apps/ios/project.yml` does the same for the phone. Tauri
   still does not embed app extensions, so for release the `.appex` gets injected
   into `Arca.app/Contents/PlugIns/` and co-signed.
3. **Entitlements & provisioning** — solved for the *passwords* extension in
   `apps/macos/` and `apps/ios/`: the AutoFill capability on **both** the
   containing app and the extension, the `group.no.sybr.vault` App Group, and a
   shared keychain access group. A passkey provider needs all of that plus
   `ProvidesPasskeys = true`, which is deliberately `false` today so Arca does
   not appear in the chooser only to fail. Distribution still needs a
   provisioning profile on the App ID and notarization.
4. **Enable on device:** System Settings → Passwords → Password Options → turn
   on "Arca". Only then does it appear in the system passkey chooser.
5. **Windows / Linux:** out of scope for now. Windows has a brand-new "plugin
   authenticator" model; Linux has no standard third-party passkey provider
   hook. macOS first.

## Security notes (feeds THREAT_MODEL.md)

- The credential private key is a P-256 scalar stored inside the encrypted vault
  and zeroized in memory; it never leaves the device.
- The extension unlocks via the OS-keychain device key gated by Touch ID (the OS
  performs the biometric as part of the AutoFill flow), so the master password is
  not needed per assertion. Same residual as T10 (device-key theft by same-user
  code) applies.
- `attestationObject` uses `fmt: "none"` — no attestation CA, no device
  identifier leaked to relying parties (privacy-preserving, and what most
  software authenticators do).
- Independent review of `passkey.rs` against the WebAuthn spec is required before
  this is used for real credentials (tracked with the overall audit).
