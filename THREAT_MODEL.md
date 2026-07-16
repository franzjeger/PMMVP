# Threat Model — Arca (Phase 1)

**Status: draft, authored alongside Phase 1.** This document is *not* a
substitute for an independent review. The project spec requires both a threat
model (this file) and an independent cryptographic/implementation audit before
real-world use. This file discharges the first; the audit remains **outstanding**
(see [Required before production](#required-before-production)).

It also records which risks are mitigated, which are accepted for Phase 1, and
which are explicitly out of scope, so reviewers and users can make an informed
decision.

## Assets (what we protect, most sensitive first)

1. **Master password** — never persisted anywhere.
2. **Master key and vault key** — 256-bit symmetric keys held in memory only
   while unlocked.
3. **Item secrets** — passwords, TOTP shared secrets, secure-note bodies.
4. **Item metadata** — titles, usernames, URLs (private, lower sensitivity).
5. **Vault shape** — item count and approximate sizes (low sensitivity).

## Trust boundaries

```
master password (user) ─► vault-core (pure, no I/O)
                              │  keys, AEAD, model
                              ▼
                          vault-store ─► vault file on disk (at rest)
                              │       └► OS keychain (device key for quick unlock)
                              ▼
                          desktop app (Tauri/Rust)  ◄── trusted
                              │  IPC (Tauri commands)
                              ▼
                          webview / UI (JS)         ◄── least trusted in-process
                              ▲
   browser extension ─► native-messaging host ─► (Phase 2) desktop IPC
```

Trusted: the user's OS and the device while the screen is unlocked, the Rust
process, the OS keychain. Less trusted: the webview JS heap, the clipboard, the
disk at rest, the browser/extension context.

## Adversaries

- **A1 — File holder.** Has the encrypted vault file (stolen/synced backup, lost
  laptop drive) but not the running process or master password.
- **A2 — Remote network attacker.** No server exists, so the only exposure is an
  exfiltrated vault file (reduces to A1). No telemetry, no outbound calls.
- **A3 — Same-user malware.** Code running with the user's privileges.
- **A4 — Privileged/physical attacker.** Root, kernel, or live-memory access.
- **A5 — Malicious web page.** Relevant to extension autofill.
- **A6 — Shoulder-surfer / clipboard sniffer.** Local observer of screen or
  clipboard.

## Threats and mitigations

| # | Threat | Adversary | Status | Mitigation / note |
|---|--------|-----------|--------|-------------------|
| T1 | Offline brute force of the vault file | A1 | **Mitigated** | Argon2id (m=64 MiB, t=3, p=4) + 256-bit keys. Strength ultimately bounded by master-password entropy. |
| T2 | Tampering with vault bytes | A1/A3 | **Mitigated** | Per-item and key-wrap XChaCha20-Poly1305; tampering fails authentication on unlock. |
| T3 | Format/variant confusion to mis-decode data | A1 | **Mitigated** | Name-tagged CBOR item payloads + versioned header; id bound as AEAD AAD. |
| T4 | Wrong-password oracle / timing side channel | A1/A6 | **Mitigated** | Poly1305 verification is constant-time; errors are indistinct ("wrong password or tampered"). |
| T5 | Secrets written to swap/hibernation | A1/A4 | **Not yet** | `mlock`/`VirtualLock` of secret memory is pending (residual). |
| T6 | Secret residue in process memory | A3/A4 | **Partial** | `zeroize` on drop for keys + plaintext; intermediate copies and un-locked pages may persist. |
| T7 | Clipboard sniffing of a copied secret | A3/A6 | **Partial** | Copy happens in Rust (never enters JS); auto-clear after a configurable timeout, only if unchanged. Plaintext is exposed for the clear window. |
| T8 | Secret exposure via the webview heap | A3/A4 | **Partial** | Secrets sent to the UI only on explicit reveal; copy stays in Rust. Revealed values and live TOTP codes transit the JS heap; CSP restricts the webview. |
| T9 | Same-user malware reading memory/keychain/file | A3 | **Out of scope** | No local password manager defends against code running as the same user; documented, not claimed. |
| T10 | Theft of the keychain device key (quick unlock) | A3/A4 | **Inherited** | Protected by the OS keychain/secure enclave; deleting the entry disables quick unlock. Master password is never stored. On macOS, quick unlock is additionally gated behind a Touch ID (device-owner) prompt — a *presence* check in front of the keychain read. Residual: the key is not yet stored in a `SecAccessControl`-protected item that the OS refuses to release without biometrics, so a same-user process (T9) could still read it directly without the prompt. |
| T11 | Autofill into a phishing origin | A5 | **Mitigated (optional consent)** | The autofill bridge enforces origin binding: a credential is released only when the page host matches the stored login's host, and only while unlocked. The bridge is loopback-only + token-authed. An **optional** per-fill in-app Allow/Deny prompt (`confirm_autofill` setting) makes the desktop app the final approver, defending even a compromised extension. Residual: a same-user process (A3/T9) could read the token file. |
| T12 | Telemetry / data exfiltration | A2 | **Mitigated** | No network code, no analytics. |
| T13 | Secrets leaked through logs/errors | A3 | **Mitigated** | Error types carry no secret material; nothing logs plaintext. |
| T14 | Metadata/length leakage from the file | A1 | **Accepted** | Items encrypted individually; CBOR is self-describing (field names present inside the AEAD); sizes are not padded. See SECURITY.md. |

## Residual risks accepted for Phase 1

- Host compromise and same-user malware (T9, A3/A4).
- Memory not locked against swap (T5/T6) until `mlock` lands.
- Transient clipboard and webview exposure (T7/T8).
- No anti-phishing on autofill (T11).
- No recovery path if the master password is lost (by design; zero-knowledge).

## Verification status

- vault-core crypto, model, TOTP, password gen, audit: unit-tested.
- Cross-platform build + full test suite: CI on Linux, Windows, macOS.
- Atomic persistence + AEAD tamper detection: tested.
- Clipboard ownership (the X11 "serves after copy returns" path): executed in CI
  under Xvfb. The Wayland path is exercised best-effort in CI under headless
  `sway`; the final **interactive cross-application paste on a real Wayland
  desktop** is an inherent manual acceptance test.
- OS keychain quick unlock: best-effort CI smoke (gnome-keyring) + manual.

## Required before production

1. **Independent cryptographic and implementation audit** — outstanding, and not
   self-closable by this project. This document is its input, not its substitute.
2. Land `mlock`/`VirtualLock` for secret memory (T5/T6).
3. Consider making the per-fill consent prompt (now available as the opt-in
   `confirm_autofill` setting; T11) the default, once its UX is validated.
4. Tighten the production CSP (remove dev `'unsafe-inline'`).
5. Complete the manual interactive paste check on real X11 and Wayland sessions.
6. Store the quick-unlock device key in a biometry-gated keychain item
   (`SecAccessControl`) so the OS itself refuses to release it without Touch ID,
   upgrading the current app-level presence gate (T10) to OS-enforced.
