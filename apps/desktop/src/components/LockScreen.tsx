import { useEffect, useRef, useState } from "react";
import { api, errorMessage, isApiError, type VaultStatus } from "../lib/api";
import { LockIcon, TouchIdIcon } from "./icons";

export function LockScreen({
  status,
  onUnlocked,
}: {
  status: VaultStatus;
  onUnlocked: () => void;
}) {
  const creating = !status.exists;
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setError(null);
    if (creating) {
      if (password.length < 8) {
        setError("Use at least 8 characters for your master password.");
        return;
      }
      if (password !== confirm) {
        setError("Passwords don't match.");
        return;
      }
    } else if (!password) {
      return;
    }
    setBusy(true);
    try {
      if (creating) await api.createVault(password);
      else await api.unlock(password);
      setPassword("");
      setConfirm("");
      onUnlocked();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  // After quick unlock FAILS past the biometric (stale device key, keychain
  // trouble), stop offering Touch ID entirely until a password unlock repairs
  // it — more prompts can only fail the same way. A storm of re-prompts here is
  // exactly the failure mode this guards against.
  const [quickBroken, setQuickBroken] = useState(false);

  const quick = async (auto = false) => {
    setBusy(true);
    if (!auto) setError(null);
    try {
      await api.quickUnlock();
      onUnlocked();
    } catch (e) {
      const code = isApiError(e) ? e.code : "";
      if (code === "biometric_failed") {
        // The user cancelled/failed the prompt itself. Quiet on the automatic
        // attempt; show the reason on a manual retry.
        if (!auto) setError(errorMessage(e));
      } else {
        // Touch ID SUCCEEDED but the unlock itself failed (stale device key
        // etc.). Always surface this and stop prompting — only the master
        // password (which self-repairs quick unlock) can get past it.
        setQuickBroken(true);
        setError(errorMessage(e));
      }
    } finally {
      setBusy(false);
    }
  };

  // Prompt for Touch ID automatically as soon as the lock screen appears (once),
  // like the system lock screen. The password field stays available as a
  // fallback if the user cancels or prefers to type. Never re-triggered by
  // focusing/clicking the password field: typing your password must not spawn
  // biometric prompts.
  const autoTried = useRef(false);
  const canBiometric =
    !creating &&
    status.quickUnlockAvailable &&
    status.biometricAvailable &&
    !quickBroken;
  useEffect(() => {
    if (autoTried.current || !canBiometric) return;
    autoTried.current = true;
    void quick(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [canBiometric]);

  return (
    <div className="flex flex-1 items-center justify-center bg-canvas">
      <div className="w-80">
        <div className="mb-6 flex flex-col items-center gap-3">
          <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-accent/15 ring-1 ring-accent/30">
            <LockIcon className="h-8 w-8 text-accent" />
          </div>
          <h1 className="text-[17px] font-semibold text-neutral-100">
            {creating ? "Create your vault" : "Unlock Passwords"}
          </h1>
          <p className="text-center text-[12px] leading-relaxed text-neutral-500">
            {creating
              ? "Your master password encrypts everything locally. It is never stored or sent anywhere. If you forget it, the vault cannot be recovered."
              : canBiometric
                ? "Use Touch ID, or enter your master password."
                : "Enter your master password to continue."}
          </p>
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
          className="space-y-2.5"
        >
          <input
            type="password"
            autoFocus
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Master password"
            className="w-full rounded-lg bg-fill/5 px-3 py-2.5 text-[14px] text-neutral-100 outline-none ring-1 ring-line/10 focus:ring-accent/60"
          />
          {creating && (
            <input
              type="password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              placeholder="Confirm master password"
              className="w-full rounded-lg bg-fill/5 px-3 py-2.5 text-[14px] text-neutral-100 outline-none ring-1 ring-line/10 focus:ring-accent/60"
            />
          )}

          {error && <p className="px-1 text-[12px] text-red-400">{error}</p>}

          <button
            type="submit"
            disabled={busy}
            className="w-full rounded-lg bg-accent py-2.5 text-[14px] font-medium text-white hover:bg-accent/90 disabled:opacity-60"
          >
            {busy ? "Please wait…" : creating ? "Create Vault" : "Unlock"}
          </button>
        </form>

        {canBiometric && (
          <button
            type="button"
            disabled={busy}
            onClick={() => void quick(false)}
            className="mt-3 flex w-full items-center justify-center gap-1.5 text-[11px] text-neutral-500 hover:text-neutral-300 disabled:opacity-60"
          >
            <TouchIdIcon className="h-3.5 w-3.5" />
            Use Touch ID
          </button>
        )}
      </div>
    </div>
  );
}
