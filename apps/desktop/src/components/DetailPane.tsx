import { useEffect, useState, type ReactNode } from "react";
import {
  api,
  errorMessage,
  type ItemDetail,
  type PasswordStrength,
} from "../lib/api";
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

const STRENGTH_STYLE: Record<PasswordStrength, { label: string; cls: string }> = {
  weak: { label: "Weak", cls: "bg-red-500/15 text-red-400" },
  fair: { label: "Fair", cls: "bg-amber-500/15 text-amber-400" },
  strong: { label: "Strong", cls: "bg-green-500/15 text-green-400" },
};

function StrengthPill({ strength }: { strength: PasswordStrength }) {
  const s = STRENGTH_STYLE[strength];
  return (
    <span
      className={`shrink-0 rounded px-1.5 py-0.5 text-[10px] font-medium ${s.cls}`}
      title="Estimated password strength"
    >
      {s.label}
    </span>
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
      className="rounded-md p-1 text-neutral-500 hover:bg-fill/5 hover:text-neutral-200"
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
              className="rounded-lg border border-hairline px-3 py-1 text-[13px] text-neutral-200 hover:bg-fill/5"
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
          // SSH keys are create-only (the private key can't change), so no Edit.
          detail.kind !== "sshKey" && (
            <button
              onClick={onEdit}
              className="rounded-lg border border-hairline px-4 py-1 text-[13px] font-medium text-neutral-200 hover:bg-fill/5"
            >
              Edit
            </button>
          )
        )}
      </div>

      {/* fields */}
      <div className="mx-8 rounded-xl bg-fill/[0.03] px-4 ring-1 ring-line/5">
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
                <span className="flex min-w-0 items-center gap-2">
                  <span className="truncate font-mono">
                    {!detail.hasPassword
                      ? "—"
                      : revealed !== null
                        ? revealed
                        : "••••••••••••••"}
                  </span>
                  {detail.passwordStrength && (
                    <StrengthPill strength={detail.passwordStrength} />
                  )}
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

        {detail.kind === "wifi" && (
          <>
            <Row label="Network">
              <div className="flex items-center justify-between gap-2">
                <span className="truncate">{detail.ssid || "—"}</span>
                {detail.ssid && (
                  <IconButton
                    title="Copy network name"
                    onClick={() =>
                      api
                        .copyToClipboard(detail.ssid)
                        .then(() => onCopy("Network name copied"))
                    }
                  >
                    <CopyIcon className="h-4 w-4" />
                  </IconButton>
                )}
              </div>
            </Row>

            <Row label="Security">
              <span className="text-neutral-300">
                {securityLabel(detail.security)}
              </span>
            </Row>

            {detail.hasPassword && (
              <Row label="Password">
                <div className="flex items-center justify-between gap-2">
                  <span className="flex min-w-0 items-center gap-2">
                    <span className="truncate font-mono">
                      {revealed !== null ? revealed : "••••••••••••••"}
                    </span>
                    {detail.passwordStrength && (
                      <StrengthPill strength={detail.passwordStrength} />
                    )}
                  </span>
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
                </div>
              </Row>
            )}

            {detail.hidden && (
              <Row label="Hidden">
                <span className="text-neutral-400">SSID not broadcast</span>
              </Row>
            )}

            {detail.notes && (
              <Row label="Notes">
                <p className="whitespace-pre-wrap break-words">{detail.notes}</p>
              </Row>
            )}

            <Row label="Join">
              <WifiQr id={detail.id} onError={onCopy} />
            </Row>
          </>
        )}

        {detail.kind === "sshKey" && <SshDetail id={detail.id} onCopy={onCopy} />}

        {detail.kind !== "login" &&
          detail.kind !== "wifi" &&
          detail.kind !== "sshKey" && (
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

function securityLabel(s: string): string {
  switch (s) {
    case "nopass":
      return "Open (no password)";
    case "WEP":
      return "WEP";
    default:
      return "WPA / WPA2 / WPA3";
  }
}

/** "Join this network" QR code, kept behind a button so the passphrase-encoding
 *  image isn't shown until asked (the SVG is generated in Rust from the secret;
 *  its markup contains only QR rectangles, no user-controlled HTML). */
function WifiQr({ id, onError }: { id: string; onError: (m: string) => void }) {
  const [svg, setSvg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const show = async () => {
    setBusy(true);
    try {
      setSvg(await api.wifiQr(id));
    } catch (e) {
      onError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  if (svg === null) {
    return (
      <button
        onClick={() => void show()}
        disabled={busy}
        className="rounded-lg border border-hairline px-3 py-1.5 text-[13px] text-neutral-200 hover:bg-fill/5 disabled:opacity-50"
      >
        {busy ? "…" : "Show QR code"}
      </button>
    );
  }
  return (
    <div className="flex flex-col items-start gap-2">
      <div
        className="h-44 w-44 rounded-lg bg-white p-2 [&>svg]:h-full [&>svg]:w-full"
        // eslint-disable-next-line react/no-danger
        dangerouslySetInnerHTML={{ __html: svg }}
      />
      <p className="text-[11px] text-neutral-600">
        Scan with a phone camera to join.
      </p>
      <button
        onClick={() => setSvg(null)}
        className="text-[12px] text-neutral-500 hover:text-neutral-300"
      >
        Hide
      </button>
    </div>
  );
}

/** SSH key detail: fingerprint, the ready-to-paste public key, and how to point
 *  ssh/git at Arca's agent. Loads the (non-secret) public material on mount. */
function SshDetail({ id, onCopy }: { id: string; onCopy: (m: string) => void }) {
  const [pub, setPub] = useState<{
    authorizedKey: string;
    fingerprint: string;
  } | null>(null);
  const [agent, setAgent] = useState<{ socket: string; available: boolean } | null>(
    null,
  );

  useEffect(() => {
    let alive = true;
    void api
      .sshPublicKey(id)
      .then((p) => alive && setPub(p))
      .catch((e) => alive && onCopy(errorMessage(e)));
    void api
      .sshAgentInfo()
      .then((a) => alive && setAgent(a))
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, [id, onCopy]);

  return (
    <>
      <Row label="Fingerprint">
        <span className="truncate font-mono text-[13px]">
          {pub?.fingerprint ?? "…"}
        </span>
      </Row>

      <Row label="Public key">
        <div className="flex items-start justify-between gap-2">
          <span className="min-w-0 break-all font-mono text-[12px] text-neutral-300">
            {pub?.authorizedKey ?? "…"}
          </span>
          {pub && (
            <IconButton
              title="Copy public key (authorized_keys line)"
              onClick={() =>
                api
                  .copyToClipboard(pub.authorizedKey)
                  .then(() => onCopy("Public key copied"))
              }
            >
              <CopyIcon className="h-4 w-4" />
            </IconButton>
          )}
        </div>
      </Row>

      {agent?.available &&
        (agent.socket.startsWith("\\\\.\\pipe") ? (
          <Row label="Agent">
            <div className="flex flex-col gap-1.5">
              <p className="text-[12px] leading-relaxed text-neutral-500">
                Windows OpenSSH (ssh / git) uses Arca's agent automatically — no
                setup — as long as Arca is unlocked. If keys don't appear, stop
                the built-in agent so Arca can own the pipe:
              </p>
              <div className="flex items-center justify-between gap-2 rounded-lg bg-fill/5 px-3 py-2 ring-1 ring-line/10">
                <code className="min-w-0 break-all font-mono text-[12px] text-neutral-200">
                  Stop-Service ssh-agent; Set-Service ssh-agent -StartupType
                  Disabled
                </code>
                <IconButton
                  title="Copy"
                  onClick={() =>
                    api
                      .copyToClipboard(
                        "Stop-Service ssh-agent; Set-Service ssh-agent -StartupType Disabled",
                      )
                      .then(() => onCopy("Command copied"))
                  }
                >
                  <CopyIcon className="h-4 w-4" />
                </IconButton>
              </div>
            </div>
          </Row>
        ) : (
          <Row label="Agent">
            <div className="flex flex-col gap-1.5">
              <p className="text-[12px] leading-relaxed text-neutral-500">
                Point ssh/git at Arca's agent, then this key signs without the
                private key ever leaving the vault (unlock Arca first):
              </p>
              <div className="flex items-center justify-between gap-2 rounded-lg bg-fill/5 px-3 py-2 ring-1 ring-line/10">
                <code className="min-w-0 break-all font-mono text-[12px] text-neutral-200">
                  export SSH_AUTH_SOCK="{agent.socket}"
                </code>
                <IconButton
                  title="Copy"
                  onClick={() =>
                    api
                      .copyToClipboard(`export SSH_AUTH_SOCK="${agent.socket}"`)
                      .then(() => onCopy("Command copied"))
                  }
                >
                  <CopyIcon className="h-4 w-4" />
                </IconButton>
              </div>
            </div>
          </Row>
        ))}
    </>
  );
}
