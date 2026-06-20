import { useEffect, useState, type ReactNode } from "react";
import {
  api,
  errorMessage,
  type Settings,
  type VaultStatus,
} from "../lib/api";
import { GearIcon } from "./icons";

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

  const importCsv = async () => {
    setBusy(true);
    try {
      const summary = await api.pickAndImportCsv();
      if (summary) {
        onToast(
          `Imported ${summary.imported}` +
            (summary.skipped ? `, skipped ${summary.skipped}` : ""),
        );
        onStatusChanged(); // refreshes the item list
      }
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
              label="Import passwords"
              hint="From a Chrome, Apple Passwords, or Firefox CSV export. Delete the CSV afterward; it holds plaintext passwords."
            >
              <button
                type="button"
                disabled={busy}
                onClick={() => void importCsv()}
                className="rounded-lg border border-hairline px-3 py-1.5 text-[13px] text-neutral-200 hover:bg-white/5 disabled:opacity-50"
              >
                Choose CSV…
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
        className="rounded-lg bg-white/5 px-2.5 py-1.5 text-[13px] text-neutral-100 outline-none ring-1 ring-white/10 focus:ring-accent/60"
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
          checked ? "bg-accent" : "bg-white/15"
        }`}
      >
        <span
          className={`absolute top-0.5 h-5 w-5 rounded-full bg-white shadow transition-transform ${
            checked ? "translate-x-[18px]" : "translate-x-0.5"
          }`}
        />
      </button>
    </Row>
  );
}
