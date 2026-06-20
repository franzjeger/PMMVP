import type { ReactNode } from "react";
import { LockIcon } from "./icons";

/**
 * Custom title bar matching the concept art: centered "🔒 Passwords" over a
 * draggable region. The macOS traffic lights are drawn by the OS (titleBarStyle
 * "Overlay"); we leave space for them on the left.
 */
export function TitleBar({ right }: { right?: ReactNode }) {
  return (
    <div className="titlebar-drag flex h-11 shrink-0 items-center border-b border-hairline bg-canvas/80 px-3">
      {/* space for the OS traffic-light buttons */}
      <div className="w-16" />
      <div className="flex flex-1 items-center justify-center gap-2 text-[13px] font-semibold text-neutral-200">
        <LockIcon className="h-4 w-4 text-neutral-400" />
        <span>Passwords</span>
      </div>
      <div className="no-drag flex w-16 items-center justify-end">{right}</div>
    </div>
  );
}
