import { useEffect, useState } from "react";
import { api, errorMessage, type Totp } from "../lib/api";
import { formatTotp } from "../lib/format";
import { CopyIcon } from "./icons";

/**
 * Live verification code. Polls the backend every second (the backend computes
 * the code from the stored secret; the secret itself never reaches the UI) and
 * renders a 30s countdown pie.
 */
export function TotpField({
  id,
  onCopy,
}: {
  id: string;
  onCopy: (msg: string) => void;
}) {
  const [totp, setTotp] = useState<Totp | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const t = await api.currentTotp(id);
        if (alive) {
          setTotp(t);
          setError(null);
        }
      } catch (e) {
        if (alive) setError(errorMessage(e));
      }
    };
    tick();
    const iv = setInterval(tick, 1000);
    return () => {
      alive = false;
      clearInterval(iv);
    };
  }, [id]);

  if (error) {
    return <span className="text-[13px] text-neutral-500">{error}</span>;
  }
  if (!totp) {
    return <span className="text-[13px] text-neutral-500">…</span>;
  }

  const pct = totp.remaining / totp.period;
  const expiring = totp.remaining <= 5;

  return (
    <div className="flex items-center gap-3">
      <span className="font-mono text-[22px] font-medium tracking-wide text-accent tabular-nums">
        {formatTotp(totp.code)}
      </span>
      <div
        title={`${totp.remaining}s remaining`}
        className="h-4 w-4 rounded-full"
        style={{
          background: `conic-gradient(${
            expiring ? "#ff453a" : "#0a84ff"
          } ${pct * 360}deg, #3a3a3c 0deg)`,
        }}
      />
      <button
        onClick={() => {
          api.copyToClipboard(totp.code).then(() => onCopy("Code copied"));
        }}
        className="rounded-md p-1 text-neutral-500 hover:bg-white/5 hover:text-neutral-200"
        title="Copy code"
      >
        <CopyIcon className="h-4 w-4" />
      </button>
    </div>
  );
}
