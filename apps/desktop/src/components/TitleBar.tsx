import type { ReactNode } from "react";
import { LockIcon } from "./icons";

/**
 * Custom title bar matching the concept art: centered "🔒 Passwords" over a
 * draggable region. The macOS traffic lights are drawn by the OS (titleBarStyle
 * "Overlay"); we leave space for them on the left.
 *
 * Window dragging uses Tauri's `data-tauri-drag-region` (it calls the native
 * `startDragging`). The CSS `-webkit-app-region: drag` approach does NOT work in
 * the macOS WKWebView. Decorative children are `pointer-events-none` so a
 * mousedown anywhere on the bar lands on the drag-region element; the right slot
 * keeps pointer events so any buttons there stay clickable.
 */
export function TitleBar({ right }: { right?: ReactNode }) {
  return (
    <div
      data-tauri-drag-region
      className="flex h-11 shrink-0 items-center border-b border-hairline bg-canvas/80 px-3"
    >
      {/* space for the OS traffic-light buttons */}
      <div data-tauri-drag-region className="pointer-events-none w-16" />
      <div
        data-tauri-drag-region
        className="pointer-events-none flex flex-1 items-center justify-center gap-2 text-[13px] font-semibold text-neutral-200"
      >
        <LockIcon className="h-4 w-4 text-neutral-400" />
        <span>Passwords</span>
      </div>
      <div className="flex w-16 items-center justify-end">{right}</div>
    </div>
  );
}
