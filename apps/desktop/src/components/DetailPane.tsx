import { useEffect, useState, type ReactNode } from "react";
import { api, errorMessage, type ItemDetail } from "../lib/api";
import { hostFromUrl, relativeTime } from "../lib/format";
import {
  CopyIcon,
  ExternalLinkIcon,
  EyeIcon,
  EyeOffIcon,
  TrashIcon,
} from "./icons";
import { Tile } from "./Tile";
import { TotpField } from "./TotpField";

function Row({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <div className="flex items-start gap-4 border-b border-hairline py-3.5 last:border-b-0">
      <div className="w-28 shrink-0 pt-0.5 text-[13px] text-neutral-500">
        {label}
      </div>
      <div className="min-w-0 flex-1 text-[14px] text-neutral-100">
        {children}
      </div>
    </div>
  );
}

function IconButton({
  title,
  onClick,
  children,
}: {
  title: string;
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      title={title}
      className="rounded-md p-1 text-neutral-500 hover:bg-white/5 hover:text-neutral-200"
    >
      {children}
    </button>
  );
}

export function DetailPane({
  detail,
  onEdit,
  onChanged,
  onCopy,
}: {
  detail: ItemDetail;
  onEdit: () => void;
  onChanged: () => void;
  onCopy: (msg: string) => void;
}) {
  const [revealed, setRevealed] = useState<string | null>(null);

  // Hide a revealed password whenever the selected item changes.
  useEffect(() => setRevealed(null), [detail.id]);

  const host = hostFromUrl(detail.url);

  const toggleReveal = async () => {
    if (revealed !== null) {
      setRevealed(null);
      return;
    }
    try {
      setRevealed(await api.revealField(detail.id, "password"));
    } catch (e) {
      onCopy(errorMessage(e));
    }
  };

  return (
    <div className="flex flex-1 flex-col overflow-y-auto bg-canvas">
      {/* header */}
      <div className="flex items-start gap-4 px-8 pb-6 pt-8">
        <Tile letter={detail.title.charAt(0).toUpperCase() || "#"} seed={detail.title || detail.id} size={56} />
        <div className="min-w-0 flex-1">
          <h1 className="truncate text-[22px] font-bold text-neutral-50">
            {detail.title || "Untitled"}
          </h1>
          {host && <p className="truncate text-[13px] text-neutral-500">{host}</p>}
        </div>
        {detail.isDeleted ? (
          <div className="flex gap-2">
            <button
              onClick={() => api.restoreItem(detail.id).then(onChanged)}
              className="rounded-lg border border-hairline px-3 py-1 text-[13px] text-neutral-200 hover:bg-white/5"
            >
              Restore
            </button>
            <button
              onClick={() => {
                if (confirm("Permanently delete this item? This cannot be undone."))
                  api.purgeItem(detail.id).then(onChanged);
              }}
              className="rounded-lg border border-red-500/40 px-3 py-1 text-[13px] text-red-400 hover:bg-red-500/10"
            >
              Delete Forever
            </button>
          </div>
        ) : (
          <button
            onClick={onEdit}
            className="rounded-lg border border-hairline px-4 py-1 text-[13px] font-medium text-neutral-200 hover:bg-white/5"
          >
            Edit
          </button>
        )}
      </div>

      {/* fields */}
      <div className="mx-8 rounded-xl bg-white/[0.03] px-4 ring-1 ring-white/5">
        {detail.kind === "login" && (
          <>
            <Row label="User name">
              <div className="flex items-center justify-between gap-2">
                <span className="truncate">{detail.username || "—"}</span>
                {detail.username && (
                  <IconButton
                    title="Copy user name"
                    onClick={() =>
                      api
                        .copyToClipboard(detail.username)
                        .then(() => onCopy("User name copied"))
                    }
                  >
                    <CopyIcon className="h-4 w-4" />
                  </IconButton>
                )}
              </div>
            </Row>

            <Row label="Password">
              <div className="flex items-center justify-between gap-2">
                <span className="truncate font-mono">
                  {!detail.hasPassword
                    ? "—"
                    : revealed !== null
                      ? revealed
                      : "••••••••••••••"}
                </span>
                {detail.hasPassword && (
                  <div className="flex items-center gap-1">
                    <IconButton
                      title={revealed !== null ? "Hide" : "Reveal"}
                      onClick={toggleReveal}
                    >
                      {revealed !== null ? (
                        <EyeOffIcon className="h-4 w-4" />
                      ) : (
                        <EyeIcon className="h-4 w-4" />
                      )}
                    </IconButton>
                    <IconButton
                      title="Copy password"
                      onClick={() =>
                        api
                          .copyField(detail.id, "password")
                          .then(() => onCopy("Password copied"))
                      }
                    >
                      <CopyIcon className="h-4 w-4" />
                    </IconButton>
                  </div>
                )}
              </div>
            </Row>

            {detail.hasTotp && (
              <Row label="Verification code">
                <TotpField id={detail.id} onCopy={onCopy} />
              </Row>
            )}

            {detail.url && (
              <Row label="Website">
                <button
                  onClick={() => api.openExternal(detail.url)}
                  className="flex items-center gap-2 text-accent hover:underline"
                >
                  <span className="truncate">{host || detail.url}</span>
                  <ExternalLinkIcon className="h-4 w-4 shrink-0" />
                </button>
              </Row>
            )}

            {detail.notes && (
              <Row label="Notes">
                <p className="whitespace-pre-wrap break-words">{detail.notes}</p>
              </Row>
            )}
          </>
        )}

        {detail.kind !== "login" && (
          <Row label="Type">
            <span className="text-neutral-400">
              {detail.kind} — viewing/editing arrives in a later phase.
            </span>
          </Row>
        )}
      </div>

      <div className="mt-4 flex items-center justify-between px-8 pb-8 text-[12px] text-neutral-600">
        <span>Last edited {relativeTime(detail.modifiedAt)}</span>
        {!detail.isDeleted && (
          <button
            onClick={() => api.deleteItem(detail.id).then(onChanged)}
            className="flex items-center gap-1.5 text-neutral-500 hover:text-red-400"
          >
            <TrashIcon className="h-4 w-4" />
            Delete
          </button>
        )}
      </div>
    </div>
  );
}
