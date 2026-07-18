import { useState } from "react";
import { api, errorMessage, type PasskeyVerifyRequest } from "../lib/api";
import { KeyIcon } from "./icons";

/**
 * Master-password prompt shown (Windows/Linux) when a passkey ceremony needs
 * user verification. The bridge thread is parked waiting, so every path must
 * resolve exactly once: a correct password approves (UV=1), Cancel/dismiss
 * denies. A wrong password keeps the dialog open for a retry.
 */
export function PasskeyVerifyDialog({
  request,
  onResolved,
  onToast,
}: {
  request: PasskeyVerifyRequest;
  onResolved: () => void;
  onToast: (msg: string) => void;
}) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const cancel = () => {
    api.cancelPasskeyVerification(request.id).catch(() => {});
    onResolved();
  };

  const submit = async () => {
    if (busy || !password) return;
    setBusy(true);
    setError(null);
    try {
      const ok = await api.verifyPasskeyApproval(request.id, password);
      if (ok) {
        onResolved();
      } else {
        setError("Incorrect master password. Try again.");
        setPassword("");
        setBusy(false);
      }
    } catch (e) {
      onToast(errorMessage(e));
      setBusy(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-6 backdrop-blur-sm"
      onMouseDown={(e) => e.target === e.currentTarget && cancel()}
    >
      <div className="w-full max-w-sm rounded-2xl border border-hairline bg-panel shadow-2xl">
        <div className="flex flex-col items-center gap-3 px-6 pb-2 pt-6 text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-accent/15 ring-1 ring-accent/30">
            <KeyIcon className="h-6 w-6 text-accent" />
          </div>
          <h2 className="text-[15px] font-semibold text-neutral-100">
            {request.isCreate
              ? "Create a new passkey?"
              : "Sign in with your passkey"}
          </h2>
          <p className="text-[13px] leading-relaxed text-neutral-400">
            {request.isCreate ? (
              <>
                Enter your master password to register a{" "}
                <span className="font-medium text-amber-300">brand-new</span>{" "}
                passkey for{" "}
                <span className="font-medium text-neutral-100">
                  {request.site}
                </span>
                .
              </>
            ) : (
              <>
                Enter your master password to sign in to{" "}
                <span className="font-medium text-neutral-100">
                  {request.site}
                </span>
                .
              </>
            )}
          </p>
        </div>

        <form
          className="px-6 pb-5 pt-3"
          onSubmit={(e) => {
            e.preventDefault();
            void submit();
          }}
        >
          <input
            autoFocus
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Master password"
            className="w-full rounded-lg border border-hairline bg-canvas px-3 py-2.5 text-[14px] text-neutral-100 outline-none focus:border-accent"
          />
          {error && <p className="mt-2 text-[12px] text-red-400">{error}</p>}
          <div className="mt-4 flex gap-2">
            <button
              type="button"
              onClick={cancel}
              className="flex-1 rounded-lg border border-hairline py-2.5 text-[13px] text-neutral-200 hover:bg-fill/5"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={busy || !password}
              className="flex-1 rounded-lg bg-accent py-2.5 text-[13px] font-medium text-white hover:bg-accent/90 disabled:opacity-50"
            >
              {busy ? "Verifying…" : "Approve"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
