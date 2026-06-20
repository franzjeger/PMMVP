import { useEffect } from "react";
import { CheckIcon } from "./icons";

/** Transient bottom-center toast (copied / cleared confirmations). */
export function Toast({
  message,
  onDone,
  duration = 1600,
}: {
  message: string | null;
  onDone: () => void;
  duration?: number;
}) {
  useEffect(() => {
    if (!message) return;
    const t = setTimeout(onDone, duration);
    return () => clearTimeout(t);
  }, [message, duration, onDone]);

  if (!message) return null;
  return (
    <div className="pointer-events-none fixed inset-x-0 bottom-6 z-50 flex justify-center">
      <div className="flex items-center gap-2 rounded-full bg-neutral-800/95 px-4 py-2 text-[13px] text-neutral-100 shadow-lg ring-1 ring-white/10 backdrop-blur">
        <CheckIcon className="h-4 w-4 text-green-400" />
        {message}
      </div>
    </div>
  );
}
