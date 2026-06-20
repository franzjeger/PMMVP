# Security

## ⚠️ Status: unaudited Phase-1 foundation

**An independent cryptographic audit and a formal threat model are REQUIRED
before this software is used to protect real-world secrets.** The design below
follows established practice and composes only well-reviewed cryptographic
crates, but "uses good building blocks" is not the same as "is secure." Until a
qualified third party has reviewed the implementation, treat this as a
demonstration/foundation, not a product.

A first-draft **threat model** now exists at [`THREAT_MODEL.md`](./THREAT_MODEL.md)
(assets, trust boundaries, adversaries, per-threat mitigations, and accepted
residual risks). It is the *input* to an audit, not a replacement for one: the
independent third-party audit remains **outstanding** and cannot be self-closed
by this project.

## Design goals

- **Zero-knowledge, local-first.** No plaintext, master password, or master key
  ever leaves the device or is written to a log. There is no server.
- **No telemetry.** The app makes no analytics or network calls of its own.
- **No secrets in errors.** Error types describe *what kind* of operation failed,
  never the data involved (see `vault-core::Error`, `CmdError`). Decryption
  failures are deliberately indistinct ("wrong password or tampered data").
- **Single product tier.** Every feature is available to every user; there is no
  licensing or feature gating anywhere in the code.

## Cryptography

Composed entirely from [RustCrypto](https://github.com/RustCrypto) crates — no
custom primitives are implemented.

| Concern            | Choice                                                    |
| ------------------ | --------------------------------------------------------- |
| KDF                | **Argon2id** (`argon2`), default m=64 MiB, t=3, p=4       |
| Master key         | 256-bit, derived from master password + 32-byte random salt |
| Vault key          | random 256-bit, **wrapped** with the master key           |
| Wrapping / items   | **XChaCha20-Poly1305** AEAD (`chacha20poly1305`)          |
| Per-item encryption| each item sealed individually; its UUID bound as **AAD**  |
| Randomness         | OS CSPRNG (`getrandom`)                                   |
| Secret comparison  | constant-time (`subtle`)                                  |
| Memory hygiene     | keys & plaintext zeroized on drop (`zeroize`)             |

- **KDF parameters are versioned** in a cleartext header so they can be raised
  over time; the wrap binds those parameters as AAD, so an attacker cannot
  substitute weaker parameters and still authenticate.
- **Wrong password / tampering** are caught by AEAD authentication (Poly1305 tag
  verification is constant-time). The vault never "partially" unlocks.
- **At-rest format** = `"SYBRVLT1"` magic + cleartext header (public KDF params +
  wrapped keys) + a list of individually-sealed items. The header carries a
  `format_version` so the layout can evolve. Each encrypted **item payload** is
  serialized with **CBOR** (self-describing, variant-tagged by name), so the
  `VaultItem` schema can gain or reorder variants without misreading existing
  data — a positional codec such as bincode could not guarantee this. (The thin
  outer container framing remains bincode.)

## Persistence & keychain

- **Atomic writes**: vault bytes are written to a sibling temp file, fsynced,
  then `rename`d over the target (directory fsynced on Unix). A crash mid-write
  can never produce a torn vault. Temp files are created `0600` on Unix.
- **Quick/biometric unlock**: a random 256-bit *device key* is stored in the OS
  keychain (macOS Keychain / Windows Credential Manager / Linux Secret Service)
  via the `keyring` crate. A device-key-wrapped copy of the vault key lives in
  the header. **The master password is never stored**; deleting the keychain
  entry disables quick-unlock.

## Application behavior

- **Secrets reach the UI only on demand.** Listing/loading an item returns
  metadata + non-secret fields; the password/TOTP secret are fetched via an
  explicit `reveal_field` call, and **copying a secret is done inside Rust**
  (`copy_field`) so the plaintext never enters the webview.
- **Auto-lock** on idle (configurable timeout) and on window blur; locking drops
  and zeroizes the in-memory vault key and plaintext items.
- **Clipboard auto-clear** after a configurable timeout (default 30 s), only if
  the clipboard still holds the value we wrote.

## Known limitations & non-goals (Phase 1)

These are explicitly **not** mitigated yet and must be part of the threat model:

- **Not audited.** No third-party cryptographic or implementation review.
- **Host trust.** A compromised OS, malware running as the same user, or a
  kernel-level attacker can read process memory and defeat any local password
  manager. We do not (yet) lock memory pages (`mlock`) against swapping;
  `zeroize` reduces but does not eliminate residual-secret exposure.
- **Webview exposure.** Revealed secrets and TOTP codes live transiently in the
  webview's JS heap; copied secrets live in the OS clipboard for the clear
  window. The CSP in `tauri.conf.json` still allows `'unsafe-inline'` styles for
  dev convenience and should be tightened for release.
- **Clipboard.** Copies go through a long-lived owner thread holding a single
  `arboard` instance for the app's lifetime, so the X11/Wayland selection stays
  served until paste or auto-clear (which wipes only if the value is unchanged).
  Verified on macOS; the X11/Wayland path is correct by design but was not
  executed in this environment, and Wayland depends on `arboard`'s Wayland
  support being present on the target.
- **Metadata & length.** Items are encrypted individually, so anyone with read
  access to the vault file can count entries and see each ciphertext's
  approximate size. The per-item payload is **self-describing** (CBOR), so field
  and variant names (`type`, `username`, ...) are present inside each blob and
  ciphertext length correlates slightly with which variant and fields are
  populated. This is all inside the AEAD and leaks nothing without the key — but
  field names are **not** secret, and the format does not pad to hide sizes.
- **KDF tuning.** Defaults (64 MiB/t=3/p=4) are reasonable but should be tuned
  to target hardware and periodically re-benchmarked.
- **Browser autofill.** The extension/native-host bridge to the app is stubbed;
  there is no anti-phishing/origin-binding on autofill yet, and no passkey logic.
- **No recovery.** By design, a forgotten master password means unrecoverable
  data. There is no key escrow or backup mechanism.

## Reporting

Report suspected vulnerabilities privately to **security@sybr.no**. Please do not
open public issues for security reports.
