// Typed bridge to the Rust backend. Every function here corresponds 1:1 to a
// `#[tauri::command]` in src-tauri. Tauri converts camelCase JS argument keys
// to snake_case Rust parameter names automatically.

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import { openUrl } from "@tauri-apps/plugin-opener";
import { open as openDialog } from "@tauri-apps/plugin-dialog";

// ---- types (mirror the Rust DTOs, which serialize camelCase) --------------

export interface VaultStatus {
  exists: boolean;
  unlocked: boolean;
  hasQuickUnlock: boolean;
  quickUnlockAvailable: boolean;
  biometricAvailable: boolean;
}

export type ItemKind = "login" | "passkey" | "sshKey" | "wifi" | "secureNote";

export interface SyncStatus {
  connected: boolean;
  account: string | null;
  lastSyncUnix: number | null;
  lastError: string | null;
}

export interface ItemSummary {
  id: string;
  kind: ItemKind;
  title: string;
  subtitle: string;
  letter: string;
  /** Normalized website host ("github.com"; empty when no URL). */
  host: string;
  hasTotp: boolean;
  isDeleted: boolean;
  modifiedAt: number;
}

export interface ItemDetail {
  id: string;
  kind: ItemKind;
  title: string;
  username: string;
  url: string;
  notes: string;
  hasPassword: boolean;
  hasTotp: boolean;
  passwordStrength: PasswordStrength | null;
  isDeleted: boolean;
  createdAt: number;
  modifiedAt: number;
  /** Wi-Fi only (empty/false for other kinds). */
  ssid: string;
  security: string;
  hidden: boolean;
}

export interface WifiInput {
  id: string | null;
  title: string;
  ssid: string;
  password: string;
  /** "WPA" | "WEP" | "nopass". */
  security: string;
  hidden: boolean;
  notes: string;
}

export interface SshPublicKey {
  authorizedKey: string;
  fingerprint: string;
  comment: string;
}

export interface SshAgentInfo {
  socket: string;
  available: boolean;
}

export type PasswordStrength = "weak" | "fair" | "strong";

export type SecurityTag = "weak" | "reused";

export interface SecurityIssue {
  id: string;
  issues: SecurityTag[];
}

export interface ImportSummary {
  imported: number;
  /** Existing logins whose password changed and was updated in place. */
  updated: number;
  /** Rows identical to an existing login, skipped (safe to re-import). */
  duplicates: number;
  skipped: number;
}

export interface Totp {
  code: string;
  period: number;
  remaining: number;
}

export interface Settings {
  autoLockSecs: number;
  lockOnBlur: boolean;
  clipboardClearSecs: number;
  confirmAutofill: boolean;
  savePrompt: boolean;
  handlePasskeys: boolean;
}

/** Payload of a `fill-consent-request` event: what the app is asking to fill. */
export interface FillConsent {
  id: string;
  site: string;
  account: string;
  title: string;
}

/** Payload of a `passkey-verify-request` event: the site (rp_id) whose passkey
 *  ceremony needs the master password to satisfy user verification. */
export interface PasskeyVerifyRequest {
  id: string;
  site: string;
  /** True when the ceremony registers a NEW passkey (vs signing in). */
  isCreate: boolean;
}

export interface LoginInput {
  id: string | null;
  title: string;
  username: string;
  password: string;
  url: string;
  totpSecret: string | null;
  notes: string;
}

export interface PasswordOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
}

/** Error shape the backend returns (`CmdError`). */
export interface ApiError {
  code: string;
  message: string;
}

export function isApiError(e: unknown): e is ApiError {
  return typeof e === "object" && e !== null && "code" in e && "message" in e;
}

export function errorMessage(e: unknown): string {
  if (isApiError(e)) return e.message;
  if (e instanceof Error) return e.message;
  return String(e);
}

/** True when running inside the Tauri webview (vs. a plain browser). */
export function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

// ---- commands -------------------------------------------------------------

export const api = {
  vaultStatus: () => invoke<VaultStatus>("vault_status"),

  createVault: (masterPassword: string) =>
    invoke<void>("create_vault", { masterPassword }),

  unlock: (masterPassword: string) => invoke<void>("unlock", { masterPassword }),
  quickUnlock: () => invoke<void>("quick_unlock"),
  enableQuickUnlock: () => invoke<void>("enable_quick_unlock"),
  disableQuickUnlock: () => invoke<void>("disable_quick_unlock"),
  changeMasterPassword: (newPassword: string) =>
    invoke<void>("change_master_password", { newPassword }),
  syncConnect: () => invoke<string>("sync_connect"),
  syncDisconnect: () => invoke<void>("sync_disconnect"),
  syncStatus: () => invoke<SyncStatus>("sync_status"),
  syncNow: () => invoke<boolean>("sync_now"),
  mergeDuplicates: () => invoke<number>("merge_duplicates"),
  lock: () => invoke<void>("lock"),
  touch: () => invoke<void>("touch"),

  listItems: (includeDeleted: boolean) =>
    invoke<ItemSummary[]>("list_items", { includeDeleted }),
  getItem: (id: string) => invoke<ItemDetail>("get_item", { id }),

  revealField: (id: string, field: "password" | "totp_secret" | "notes") =>
    invoke<string>("reveal_field", { id, field }),
  copyField: (id: string, field: "password" | "totp_secret" | "notes") =>
    invoke<void>("copy_field", { id, field }),
  copyToClipboard: (text: string) => invoke<void>("copy_to_clipboard", { text }),

  upsertItem: (input: LoginInput) => invoke<string>("upsert_item", { input }),
  upsertWifi: (input: WifiInput) => invoke<string>("upsert_wifi", { input }),
  /** SVG string of a "join this network" QR code (passphrase encoded in Rust,
   *  never crossing to the webview as readable text). */
  wifiQr: (id: string) => invoke<string>("wifi_qr", { id }),
  generateSshKey: (comment: string) =>
    invoke<string>("generate_ssh_key", { comment }),
  sshPublicKey: (id: string) => invoke<SshPublicKey>("ssh_public_key", { id }),
  sshAgentInfo: () => invoke<SshAgentInfo>("ssh_agent_info"),
  deleteItem: (id: string) => invoke<void>("delete_item", { id }),
  restoreItem: (id: string) => invoke<void>("restore_item", { id }),
  purgeItem: (id: string) => invoke<void>("purge_item", { id }),

  currentTotp: (id: string) => invoke<Totp>("current_totp", { id }),
  securityReport: () => invoke<SecurityIssue[]>("security_report"),
  generate: (options: PasswordOptions) => invoke<string>("generate", { options }),

  importLogins: (path: string) => invoke<ImportSummary>("import_logins", { path }),
  openPasswordsApp: () => invoke<void>("open_passwords_app"),

  getSettings: () => invoke<Settings>("get_settings"),
  setSettings: (settings: Settings) => invoke<void>("set_settings", { settings }),

  resolveAutofillConsent: (id: string, approved: boolean) =>
    invoke<void>("resolve_autofill_consent", { id, approved }),

  /** Verify the master password to approve a pending passkey ceremony
   *  (Windows/Linux). Resolves to `true` if the password was correct (and the
   *  ceremony is approved); `false` lets the dialog show a retry hint. */
  verifyPasskeyApproval: (id: string, masterPassword: string) =>
    invoke<boolean>("verify_passkey_approval", { id, masterPassword }),

  /** Cancel a pending passkey verification (user dismissed the dialog). Uses a
   *  dedicated command — NOT resolveAutofillConsent — so the passkey UV channel
   *  is never touched by the presence-only consent path. */
  cancelPasskeyVerification: (id: string) =>
    invoke<void>("cancel_passkey_verification", { id }),

  openExternal: (url: string) => openUrl(url),

  /**
   * Open a native file picker for a CSV and import it. The file is read in Rust,
   * so exported plaintext passwords never enter the webview. Returns `null` if
   * the user cancels the picker.
   *
   * The picker blurs the main window, which would otherwise trigger
   * lock-on-blur and lock the vault mid-import; we suppress that around the
   * dialog.
   */
  pickAndImportCsv: async (): Promise<ImportSummary | null> => {
    await invoke<void>("set_blur_lock_suppressed", { suppressed: true });
    try {
      const path = await openDialog({
        multiple: false,
        directory: false,
        filters: [{ name: "CSV", extensions: ["csv"] }],
      });
      if (typeof path !== "string") return null;
      return await invoke<ImportSummary>("import_logins", { path });
    } finally {
      await invoke<void>("set_blur_lock_suppressed", { suppressed: false });
    }
  },
};

// ---- events ---------------------------------------------------------------

/** Fired by the backend when the vault auto-locks (idle or window blur). */
export function onVaultLocked(cb: (reason: string) => void): Promise<UnlistenFn> {
  return listen<string>("vault-locked", (e) => cb(e.payload));
}

/** Fired after a copied secret is auto-cleared from the clipboard. */
export function onClipboardCleared(cb: () => void): Promise<UnlistenFn> {
  return listen("clipboard-cleared", () => cb());
}

/** Fired after a credential is autofilled into the browser (for visibility). */
export function onAutofilled(cb: (what: string) => void): Promise<UnlistenFn> {
  return listen<string>("autofilled", (e) => cb(e.payload));
}

/** Fired when a login is saved/updated from the browser (save-on-submit), so
 *  the UI can refresh its item list. */
export function onLoginSaved(cb: (host: string) => void): Promise<UnlistenFn> {
  return listen<string>("login-saved", (e) => cb(e.payload));
}

/** Fired when a passkey is registered ("created") or used to sign in ("used")
 *  via the browser bridge, so the UI can refresh its item list. */
/** Fired when a background sync merged in changes from another device. */
export function onSyncMerged(cb: () => void): Promise<UnlistenFn> {
  return listen("sync-merged", () => cb());
}

export function onPasskeyChanged(
  cb: (rp: string, kind: "created" | "used") => void,
): Promise<UnlistenFn> {
  const created = listen<string>("passkey-created", (e) =>
    cb(e.payload, "created"),
  );
  const used = listen<string>("passkey-used", (e) => cb(e.payload, "used"));
  return Promise.all([created, used]).then(
    (unls) => () => unls.forEach((u) => u()),
  );
}

/**
 * Fired when a fill needs the user's explicit approval (confirm-autofill on).
 * Answer with `api.resolveAutofillConsent(id, approved)`.
 */
export function onFillConsentRequest(
  cb: (req: FillConsent) => void,
): Promise<UnlistenFn> {
  return listen<FillConsent>("fill-consent-request", (e) => cb(e.payload));
}

/**
 * Fired (Windows/Linux) when a passkey ceremony needs user verification. Show a
 * master-password prompt and answer with `api.verifyPasskeyApproval(id, pw)`;
 * cancel with `api.cancelPasskeyVerification(id)`.
 */
export function onPasskeyVerifyRequest(
  cb: (req: PasskeyVerifyRequest) => void,
): Promise<UnlistenFn> {
  return listen<PasskeyVerifyRequest>("passkey-verify-request", (e) =>
    cb(e.payload),
  );
}
