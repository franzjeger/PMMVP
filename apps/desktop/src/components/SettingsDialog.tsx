import { useEffect, useState, type ReactNode } from "react";
import {
  api,
  errorMessage,
  type Settings,
  type VaultStatus,
} from "../lib/api";
import { GearIcon } from "./icons";
import { ImportDialog } from "./ImportDialog";

const AUTO_LOCK_OPTIONS = [
  { label: "Never", value: 0 },
  { label: "1 minute", value: 60 },
  { label: "5 minutes", value: 300 },
  { label: "15 minutes", value: 900 },
  { label: "30 minutes", value: 1800 },
];

const CLIPBOARD_OPTIONS = [
  { label: "Never", value: 0 },
  { label: "15 seconds", value: 15 },
  { label: "30 seconds", value: 30 },
  { label: "60 seconds", value: 60 },
];

export function SettingsDialog({
  status,
  onClose,
  onStatusChanged,
  onToast,
}: {
  status: VaultStatus;
  onClose: () => void;
  onStatusChanged: () => void;
  onToast: (msg: string) => void;
}) {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [quickUnlock, setQuickUnlock] = useState(status.hasQuickUnlock);
  const [busy, setBusy] = useState(false);
  const [importOpen, setImportOpen] = useState(false);

  useEffect(() => {
    api
      .getSettings()
      .then(setSettings)
      .catch((e) => onToast(errorMessage(e)));
  }, [onToast]);

  // Apply + persist a settings change immediately.
  const apply = (patch: Partial<Settings>) => {
    if (!settings) return;
    const next = { ...settings, ...patch };
    setSettings(next);
    api.setSettings(next).catch((e) => onToast(errorMessage(e)));
  };

  const [pwOpen, setPwOpen] = useState(false);
  const [newPw, setNewPw] = useState("");
  const [confirmPw, setConfirmPw] = useState("");

  const changePassword = async () => {
    if (newPw.length < 8) {
      onToast("Use at least 8 characters");
      return;
    }
    if (newPw !== confirmPw) {
      onToast("Passwords don't match");
      return;
    }
    setBusy(true);
    try {
      await api.changeMasterPassword(newPw);
      setNewPw("");
      setConfirmPw("");
      setPwOpen(false);
      onToast("Master password changed");
    } catch (e) {
      onToast(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const toggleQuickUnlock = async () => {
    setBusy(true);
    try {
      if (quickUnlock) {
        await api.disableQuickUnlock();
        setQuickUnlock(false);
        onToast("Quick unlock disabled");
      } else {
        await api.enableQuickUnlock();
        setQuickUnlock(true);
        onToast("Quick unlock enabled");
      }
      onStatusChanged();
    } catch (e) {
      onToast(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-40 flex items-center justify-center bg-black/50 p-6 backdrop-blur-sm"
      onMouseDown={(e) => e.target === e.currentTarget && onClose()}
    >
      <div className="w-full max-w-md rounded-2xl border border-hairline bg-panel shadow-2xl">
        <div className="flex items-center gap-2 border-b border-hairline px-5 py-3.5">
          <GearIcon className="h-5 w-5 text-accent" />
          <h2 className="text-[15px] font-semibold text-neutral-100">Settings</h2>
        </div>

        {!settings ? (
          <div className="px-5 py-10 text-center text-[13px] text-neutral-500">
            Loading…
          </div>
        ) : (
          <div className="px-5 py-2">
            <SelectRow
              label="Auto-lock when idle"
              value={settings.autoLockSecs}
              options={AUTO_LOCK_OPTIONS}
              onChange={(v) => apply({ autoLockSecs: v })}
            />
            <ToggleRow
              label="Lock when window loses focus"
              checked={settings.lockOnBlur}
              onChange={(v) => apply({ lockOnBlur: v })}
            />
            <SelectRow
              label="Clear clipboard after copy"
              value={settings.clipboardClearSecs}
              options={CLIPBOARD_OPTIONS}
              onChange={(v) => apply({ clipboardClearSecs: v })}
            />
            <ToggleRow
              label="Quick unlock (OS keychain)"
              hint="Unlock without your master password using the system keychain. The master password is never stored."
              checked={quickUnlock}
              disabled={busy}
              onChange={() => void toggleQuickUnlock()}
            />
            <Row
              label="Change master password"
              hint="Re-keys the vault under a new password after a biometric check. Quick unlock keeps working; other devices need the new password after the next sync/seed."
            >
              <button
                type="button"
                disabled={busy}
                onClick={() => setPwOpen((v) => !v)}
                className="rounded-lg border border-hairline px-3 py-1.5 text-[13px] text-neutral-200 hover:bg-fill/5 disabled:opacity-50"
              >
                {pwOpen ? "Cancel" : "Change…"}
              </button>
            </Row>
            {pwOpen && (
              <div className="mb-2 flex flex-col gap-2 rounded-lg bg-fill/5 p-3 ring-1 ring-line/10">
                <input
                  type="password"
                  placeholder="New master password (min. 8 characters)"
                  value={newPw}
                  autoFocus
                  onChange={(e) => setNewPw(e.target.value)}
                  className="rounded-lg bg-fill/5 px-3 py-2 text-[13px] text-neutral-100 outline-none ring-1 ring-line/10 placeholder-neutral-600 focus:ring-accent/60"
                />
                <input
                  type="password"
                  placeholder="Repeat new master password"
                  value={confirmPw}
                  onChange={(e) => setConfirmPw(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && void changePassword()}
                  className="rounded-lg bg-fill/5 px-3 py-2 text-[13px] text-neutral-100 outline-none ring-1 ring-line/10 placeholder-neutral-600 focus:ring-accent/60"
                />
                <button
                  type="button"
                  disabled={busy || newPw.length === 0}
                  onClick={() => void changePassword()}
                  className="self-end rounded-lg bg-accent px-4 py-1.5 text-[13px] font-medium text-white hover:bg-accent/90 disabled:opacity-50"
                >
                  Set new password
                </button>
              </div>
            )}
            <ToggleRow
              label="Confirm before autofill"
              hint="Ask for an explicit Allow/Deny in this app before a password is filled into the browser. Off by default; autofill is already limited to the matching site while unlocked."
              checked={settings.confirmAutofill}
              onChange={(v) => apply({ confirmAutofill: v })}
            />
            <ToggleRow
              label="Offer to save new logins"
              hint="When you sign in on a site the vault doesn't know, offer to save it (or update a changed password). On by default."
              checked={settings.savePrompt}
              onChange={(v) => apply({ savePrompt: v })}
            />
            <Row
              label="Import passwords"
              hint="From Safari/Apple Passwords, Chrome, Brave, Edge, Firefox, or any CSV export. Safe to re-import: duplicates are skipped."
            >
              <button
                type="button"
                disabled={busy}
                onClick={() => setImportOpen(true)}
                className="rounded-lg border border-hairline px-3 py-1.5 text-[13px] text-neutral-200 hover:bg-fill/5 disabled:opacity-50"
              >
                Import…
              </button>
            </Row>
          </div>
        )}

        <div className="flex justify-end border-t border-hairline px-5 py-3">
          <button
            onClick={onClose}
            className="rounded-lg bg-accent px-4 py-1.5 text-[13px] font-medium text-white hover:bg-accent/90"
          >
            Done
          </button>
        </div>
      </div>

      {importOpen && (
        <ImportDialog
          onClose={() => setImportOpen(false)}
          onImported={onStatusChanged}
          onToast={onToast}
        />
      )}
    </div>
  );
}

function Row({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <div className="flex items-center justify-between gap-4 border-b border-hairline py-3 last:border-b-0">
      <div className="min-w-0">
        <div className="text-[13px] text-neutral-100">{label}</div>
        {hint && (
          <div className="mt-0.5 text-[11px] leading-snug text-neutral-500">
            {hint}
          </div>
        )}
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  );
}

function SelectRow({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: number;
  options: { label: string; value: number }[];
  onChange: (v: number) => void;
}) {
  return (
    <Row label={label}>
      <select
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="rounded-lg bg-fill/5 px-2.5 py-1.5 text-[13px] text-neutral-100 outline-none ring-1 ring-line/10 focus:ring-accent/60"
      >
        {options.map((o) => (
          <option key={o.value} value={o.value} className="bg-panel">
            {o.label}
          </option>
        ))}
      </select>
    </Row>
  );
}

function ToggleRow({
  label,
  hint,
  checked,
  disabled,
  onChange,
}: {
  label: string;
  hint?: string;
  checked: boolean;
  disabled?: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <Row label={label} hint={hint}>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={`relative h-6 w-10 rounded-full transition-colors disabled:opacity-50 ${
          checked ? "bg-accent" : "bg-fill/15"
        }`}
      >
        {/* left-0 anchors the knob: without it, WKWebView derives the static
            position from the button's centered content, so the knob renders
            right-of-center regardless of state. */}
        <span
          className={`absolute left-0 top-0.5 h-5 w-5 rounded-full bg-white shadow transition-transform ${
            checked ? "translate-x-[18px]" : "translate-x-0.5"
          }`}
        />
      </button>
    </Row>
  );
}
