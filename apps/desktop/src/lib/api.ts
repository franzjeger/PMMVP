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
}

export type ItemKind = "login" | "passkey" | "secureNote";

export interface ItemSummary {
  id: string;
  kind: ItemKind;
  title: string;
  subtitle: string;
  letter: string;
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
}

export type PasswordStrength = "weak" | "fair" | "strong";

export type SecurityTag = "weak" | "reused";

export interface SecurityIssue {
  id: string;
  issues: SecurityTag[];
}

export interface ImportSummary {
  imported: number;
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
  deleteItem: (id: string) => invoke<void>("delete_item", { id }),
  restoreItem: (id: string) => invoke<void>("restore_item", { id }),
  purgeItem: (id: string) => invoke<void>("purge_item", { id }),

  currentTotp: (id: string) => invoke<Totp>("current_totp", { id }),
  securityReport: () => invoke<SecurityIssue[]>("security_report"),
  generate: (options: PasswordOptions) => invoke<string>("generate", { options }),

  importLogins: (path: string) => invoke<ImportSummary>("import_logins", { path }),

  getSettings: () => invoke<Settings>("get_settings"),
  setSettings: (settings: Settings) => invoke<void>("set_settings", { settings }),

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
