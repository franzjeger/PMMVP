import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import type { UnlistenFn } from "@tauri-apps/api/event";

import {
  api,
  errorMessage,
  isTauri,
  onAutofilled,
  onBreachProgress,
  onClipboardCleared,
  onFillConsentRequest,
  onLoginSaved,
  onPasskeyChanged,
  onPasskeySuppressed,
  onPasskeyRegistrationBlocked,
  onPasskeyVerifyRequest,
  onSyncMerged,
  onAutoFillPublished,
  onUnlockRequested,
  onVaultLocked,
  onVaultUnlocked,
  type FillConsent,
  type PasskeyVerifyRequest,
  type ItemDetail,
  type ItemSummary,
  type SecurityIssue,
  type SecurityTag,
  type VaultStatus,
} from "./lib/api";
import {
  CATEGORIES,
  filterByCategory,
  type CategoryId,
} from "./lib/categories";
import { displayOrder } from "./lib/grouping";

import { TitleBar } from "./components/TitleBar";
import { Sidebar } from "./components/Sidebar";
import { EntryList } from "./components/EntryList";
import { DetailPane } from "./components/DetailPane";
import { LockScreen } from "./components/LockScreen";
import { EditDialog } from "./components/EditDialog";
import { WifiEditDialog } from "./components/WifiEditDialog";
import { SshKeyDialog } from "./components/SshKeyDialog";
import { NoteEditDialog } from "./components/NoteEditDialog";
import { SettingsDialog } from "./components/SettingsDialog";
import { ConsentDialog } from "./components/ConsentDialog";
import { PasskeyVerifyDialog } from "./components/PasskeyVerifyDialog";
import { TouchIdBanner } from "./components/TouchIdBanner";
import { Toast } from "./components/Toast";
import { KeyIcon } from "./components/icons";

export default function App() {
  const [status, setStatus] = useState<VaultStatus | null>(null);
  const [items, setItems] = useState<ItemSummary[]>([]);
  const [security, setSecurity] = useState<SecurityIssue[]>([]);
  const [category, setCategory] = useState<CategoryId>("all");
  const [search, setSearch] = useState("");
  /// True when the vault locked on its own (idle or blur) rather than because
  /// the app was just opened. Decides whether the lock screen may ask for Touch
  /// ID by itself.
  const [autoLocked, setAutoLocked] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<ItemDetail | null>(null);
  const [editing, setEditing] = useState<{
    id: string | null;
    kind: "login" | "wifi" | "ssh" | "note";
  } | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [consent, setConsent] = useState<FillConsent | null>(null);
  const [passkeyVerify, setPasskeyVerify] = useState<PasskeyVerifyRequest | null>(
    null,
  );
  const [toast, setToast] = useState<string | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [breaches, setBreaches] = useState<Map<string, number>>(new Map());
  const [breachBusy, setBreachBusy] = useState(false);
  const [breachProgress, setBreachProgress] = useState<{
    done: number;
    total: number;
  } | null>(null);

  const loadItems = useCallback(async () => {
    try {
      const [list, report] = await Promise.all([
        api.listItems(true),
        api.securityReport(),
      ]);
      setItems(list);
      setSecurity(report);
    } catch (e) {
      setToast(errorMessage(e));
    }
  }, []);

  const refreshStatus = useCallback(async () => {
    try {
      const s = await api.vaultStatus();
      setStatus(s);
      if (s.unlocked) await loadItems();
    } catch (e) {
      setToast(errorMessage(e));
    }
  }, [loadItems]);

  useEffect(() => {
    if (isTauri()) void refreshStatus();
    else
      setStatus({
        exists: false,
        unlocked: false,
        hasQuickUnlock: false,
        quickUnlockAvailable: false,
        biometricAvailable: false,
      });
  }, [refreshStatus]);

  // Backend-driven auto-lock + clipboard events.
  useEffect(() => {
    const pending: Promise<UnlistenFn>[] = [
      onVaultLocked(() => {
        // The reason has always been on the wire and nobody read it. An
        // automatic lock must not be followed by a Touch ID sheet: you did not
        // ask for anything, so nothing should ask you for a fingerprint.
        setAutoLocked(true);
        setSelectedId(null);
        setSelectedIds(new Set());
        setBreaches(new Map());
        setDetail(null);
        setItems([]);
        setSecurity([]);
        setPasskeyVerify(null);
        void refreshStatus();
      }),
      // Somebody out there is waiting on this vault. Clearing the flag lets the
      // lock screen ask for Touch ID again — the request came from the user, at
      // a password field, which is precisely the case the suppression is not
      // meant to cover.
      onUnlockRequested(() => setAutoLocked(false)),
      // Unlocked from outside the window (macOS/Windows): pick up the new state
      // instead of showing a lock screen for a vault that is open.
      onVaultUnlocked(() => {
        setAutoLocked(false);
        void refreshStatus();
      }),
      onAutoFillPublished(({ count, ok, message }) => {
        // Silent on the happy path — nobody needs a receipt every unlock. Loud
        // when the OS took nothing, which is the case that looks like a bug in
        // Arca and is a switch in System Settings.
        if (!ok) {
          setToast(`${message}. System Settings ▸ General ▸ AutoFill & Passwords.`);
        } else if (count === 0) {
          setToast("No logins with a website to offer in system AutoFill.");
        }
      }),
      onClipboardCleared(() => setToast("Clipboard cleared")),
      onAutofilled((what) => setToast(`Autofilled ${what}`)),
      onPasskeySuppressed((site) =>
        setToast(`Stopped asking about passkeys for ${site}. Quit Arca to reset.`),
      ),
      onPasskeyRegistrationBlocked((site) =>
        setToast(
          `${site} tried to add a passkey you already have here. Delete Arca's copy first to replace it.`,
        ),
      ),
      onFillConsentRequest((req) => setConsent(req)),
      onPasskeyVerifyRequest((req) => setPasskeyVerify(req)),
      onPasskeyChanged((rp, kind) => {
        if (kind === "created") {
          setToast(`Passkey saved for ${rp}`);
          void loadItems(); // a new passkey was written via the browser bridge
        } else {
          setToast(`Signed in to ${rp} with passkey`);
        }
      }),
      onLoginSaved((host) => {
        setToast(`Saved login for ${host}`);
        void loadItems();
      }),
      onSyncMerged(() => {
        setToast("Synced changes from another device");
        void loadItems();
      }),
    ];
    return () => {
      pending.forEach((p) => p.then((u) => u()).catch(() => {}));
    };
  }, [refreshStatus, loadItems]);

  // Treat genuine interaction as activity so idle auto-lock is accurate.
  useEffect(() => {
    if (!status?.unlocked) return;
    let last = 0;
    const onActivity = () => {
      const now = Date.now();
      if (now - last > 15000) {
        last = now;
        api.touch().catch(() => {});
      }
    };
    window.addEventListener("pointerdown", onActivity);
    window.addEventListener("pointermove", onActivity);
    window.addEventListener("keydown", onActivity);
    return () => {
      window.removeEventListener("pointerdown", onActivity);
      window.removeEventListener("pointermove", onActivity);
      window.removeEventListener("keydown", onActivity);
    };
  }, [status?.unlocked]);

  // Map of item id -> security issue tags, for the Security view + badges.
  const issuesById = useMemo(() => {
    const m = new Map<string, SecurityTag[]>();
    for (const s of security) m.set(s.id, [...s.issues]);
    for (const id of breaches.keys()) {
      const tags = m.get(id) ?? [];
      if (!tags.includes("breached")) tags.push("breached");
      m.set(id, tags);
    }
    return m;
  }, [security, breaches]);

  // Per-category counts shown in the sidebar.
  const counts = useMemo(() => {
    const c = {} as Record<CategoryId, number>;
    for (const cat of CATEGORIES) {
      c[cat.id] =
        cat.id === "security"
          ? security.length
          : filterByCategory(items, cat.id).length;
    }
    return c;
  }, [items, security]);

  const visible = useMemo(() => {
    const base =
      category === "security"
        ? items.filter((i) => !i.isDeleted && issuesById.has(i.id))
        : filterByCategory(items, category);
    const q = search.trim().toLowerCase();
    if (!q) return base;
    return base.filter(
      (i) =>
        i.title.toLowerCase().includes(q) ||
        i.subtitle.toLowerCase().includes(q),
    );
  }, [items, category, search, issuesById]);

  // ---- multi-select (bulk restore / delete) --------------------------------
  const clearSelection = useCallback(() => setSelectedIds(new Set()), []);

  // On-demand HaveIBeenPwned k-anonymity check over all login passwords.
  const runBreachCheck = useCallback(async () => {
    setBreachBusy(true);
    setBreachProgress(null);
    // One request per distinct hash prefix, so a big vault takes a while.
    // Report progress rather than spinning silently for a minute.
    const unlisten = await onBreachProgress((done, total) =>
      setBreachProgress({ done, total }),
    );
    try {
      const report = await api.checkBreaches();
      setBreaches(new Map(report.hits.map((h) => [h.id, h.count])));
      const n = report.hits.length;
      const found = n
        ? `${n} password${n === 1 ? "" : "s"} found in known breaches`
        : "No breached passwords found";
      // Never imply an all-clear for logins we could not actually check.
      setToast(
        report.unchecked
          ? `${found} — but ${report.unchecked} could not be checked (network); try again`
          : found,
      );
    } catch (e) {
      setToast(errorMessage(e));
    } finally {
      unlisten();
      setBreachBusy(false);
      setBreachProgress(null);
    }
  }, []);

  const toggleSelect = useCallback((id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  // Header checkbox: select every visible item, or clear if all already picked.
  const selectAllVisible = useCallback(() => {
    setSelectedIds((prev) =>
      prev.size >= visible.length && visible.every((i) => prev.has(i.id))
        ? new Set()
        : new Set(visible.map((i) => i.id)),
    );
  }, [visible]);

  // Run a per-item action over the current selection, in small parallel
  // batches so hundreds of items don't fire hundreds of IPC calls at once.
  const runBulk = useCallback(
    async (fn: (id: string) => Promise<void>, verb: string) => {
      const ids = [...selectedIds];
      if (ids.length === 0) return;
      let ok = 0;
      const CHUNK = 20;
      for (let i = 0; i < ids.length; i += CHUNK) {
        const results = await Promise.allSettled(
          ids.slice(i, i + CHUNK).map((id) => fn(id)),
        );
        ok += results.filter((r) => r.status === "fulfilled").length;
      }
      await loadItems();
      clearSelection();
      // Surface partial failures instead of silently under-reporting.
      const failed = ids.length - ok;
      setToast(
        failed > 0
          ? `${verb} ${ok} of ${ids.length} (${failed} failed)`
          : `${verb} ${ok} item${ok === 1 ? "" : "s"}`,
      );
    },
    [selectedIds, loadItems, clearSelection],
  );

  // Keep a sensible selection as the visible list changes. Pick the item the
  // list actually renders first (grouped + sorted order), not backend order.
  useEffect(() => {
    if (visible.length === 0) {
      setSelectedId(null);
      return;
    }
    if (!selectedId || !visible.some((i) => i.id === selectedId)) {
      setSelectedId(displayOrder(visible)[0].id);
    }
  }, [visible, selectedId]);

  // Load detail for the selected item.
  useEffect(() => {
    if (!selectedId) {
      setDetail(null);
      return;
    }
    let alive = true;
    api
      .getItem(selectedId)
      .then((d) => alive && setDetail(d))
      .catch(() => alive && setDetail(null));
    return () => {
      alive = false;
    };
  }, [selectedId, items]);

  const handleLock = async () => {
    await api.lock().catch(() => {});
    await refreshStatus();
  };

  const handleSaved = async (id: string) => {
    setEditing(null);
    await loadItems();
    setCategory("all");
    setSelectedId(id);
  };

  const handleChanged = async () => {
    await loadItems();
  };

  if (!isTauri()) {
    return <BrowserNotice />;
  }

  if (!status) {
    return (
      <Shell>
        <div className="flex flex-1 items-center justify-center text-[13px] text-neutral-500">
          Loading…
        </div>
      </Shell>
    );
  }

  if (!status.unlocked) {
    return (
      <Shell>
        <LockScreen
          status={status}
          autoLocked={autoLocked}
          onUnlocked={() => {
            setAutoLocked(false);
            void refreshStatus();
          }}
        />
      </Shell>
    );
  }

  const categoryLabel =
    CATEGORIES.find((c) => c.id === category)?.label ?? "All";
  const emptyHint =
    category === "wifi"
      ? "No Wi-Fi networks yet — click + to add one."
      : category === "sshKeys"
        ? "No SSH keys yet — click + to generate one."
        : category === "notes"
          ? "No notes yet — click + to write one."
          : category === "security"
        ? "No weak or reused passwords. Nice."
        : category === "deleted"
          ? "Trash is empty."
          : "No items yet — click + to add one.";

  return (
    <Shell>
      {status.biometricAvailable && !status.hasQuickUnlock && (
        <TouchIdBanner onEnabled={refreshStatus} onToast={setToast} />
      )}
      <div className="flex flex-1 overflow-hidden">
        <Sidebar
          counts={counts}
          active={category}
          onSelect={(c) => {
            setCategory(c);
            setSelectedId(null);
            clearSelection();
          }}
          search={search}
          // Clear the multi-selection when the search narrows/changes, so a
          // bulk action can never hit items scrolled out of view by a filter
          // (the confirm count and the acted-on set would otherwise diverge —
          // irreversible for a Trash purge). Mirrors the category switch above.
          onSearch={(q) => {
            setSearch(q);
            if (selectedIds.size) clearSelection();
          }}
          onLock={handleLock}
          onOpenSettings={() => setSettingsOpen(true)}
        />
        <EntryList
          title={categoryLabel}
          items={visible}
          selectedId={selectedId}
          onSelect={setSelectedId}
          banner={
            category === "security" ? (
              <div className="flex items-center gap-2 border-y border-hairline bg-fill/[0.03] px-3 py-2 text-[12px]">
                <button
                  onClick={() => void runBreachCheck()}
                  disabled={breachBusy}
                  className="rounded-md border border-hairline px-2.5 py-1 text-neutral-200 hover:bg-fill/5 disabled:opacity-50"
                >
                  {breachBusy
                    ? breachProgress
                      ? `Checking ${breachProgress.done} of ${breachProgress.total}…`
                      : "Checking breaches…"
                    : breaches.size
                      ? "Re-check breaches"
                      : "Check passwords for breaches"}
                </button>
                <span className="text-neutral-500">
                  via HaveIBeenPwned (only a hash prefix is sent)
                </span>
              </div>
            ) : undefined
          }
          onAdd={() =>
            setEditing({
              id: null,
              kind:
                category === "wifi"
                  ? "wifi"
                  : category === "sshKeys"
                    ? "ssh"
                    : category === "notes"
                      ? "note"
                      : "login",
            })
          }
          emptyHint={emptyHint}
          issuesById={category === "security" ? issuesById : undefined}
          selectedIds={selectedIds}
          onToggleSelect={toggleSelect}
          onSelectAll={selectAllVisible}
          onClearSelection={clearSelection}
          onSelectRange={(ids) => setSelectedIds(new Set(ids))}
          isDeletedView={category === "deleted"}
          onBulkDelete={() => void runBulk(api.deleteItem, "Deleted")}
          onBulkRestore={() => void runBulk(api.restoreItem, "Restored")}
          onBulkPurge={() => {
            if (
              confirm(
                `Permanently delete ${selectedIds.size} item${
                  selectedIds.size === 1 ? "" : "s"
                }? This cannot be undone.`,
              )
            )
              void runBulk(api.purgeItem, "Permanently deleted");
          }}
        />
        {detail ? (
          <DetailPane
            detail={detail}
            onEdit={() =>
              setEditing({
                id: detail.id,
                kind:
                  detail.kind === "wifi"
                    ? "wifi"
                    : detail.kind === "secureNote"
                      ? "note"
                      : "login",
              })
            }
            onChanged={handleChanged}
            onCopy={setToast}
          />
        ) : (
          <EmptyDetail />
        )}
      </div>

      {settingsOpen && (
        <SettingsDialog
          status={status}
          onClose={() => setSettingsOpen(false)}
          onStatusChanged={refreshStatus}
          onToast={setToast}
        />
      )}
      {editing &&
        (editing.kind === "ssh" ? (
          <SshKeyDialog
            onClose={() => setEditing(null)}
            onSaved={handleSaved}
          />
        ) : editing.kind === "note" ? (
          <NoteEditDialog
            itemId={editing.id}
            onClose={() => setEditing(null)}
            onSaved={handleSaved}
          />
        ) : editing.kind === "wifi" ? (
          <WifiEditDialog
            itemId={editing.id}
            onClose={() => setEditing(null)}
            onSaved={handleSaved}
          />
        ) : (
          <EditDialog
            itemId={editing.id}
            onClose={() => setEditing(null)}
            onSaved={handleSaved}
          />
        ))}
      {consent && (
        <ConsentDialog
          request={consent}
          onResolved={() => setConsent(null)}
          onToast={setToast}
        />
      )}
      {passkeyVerify && (
        <PasskeyVerifyDialog
          request={passkeyVerify}
          onResolved={() => setPasskeyVerify(null)}
          onToast={setToast}
        />
      )}
      <Toast message={toast} onDone={() => setToast(null)} />
    </Shell>
  );
}

function Shell({ children }: { children: ReactNode }) {
  return (
    <div className="flex h-screen w-screen flex-col overflow-hidden bg-canvas text-neutral-100">
      <TitleBar />
      {children}
    </div>
  );
}

function EmptyDetail() {
  return (
    <div className="flex flex-1 flex-col items-center justify-center bg-canvas text-neutral-600">
      <KeyIcon className="h-10 w-10" />
      <p className="mt-3 text-[13px]">Select an item to view its details</p>
    </div>
  );
}

function BrowserNotice() {
  return (
    <div className="flex h-screen w-screen items-center justify-center bg-canvas p-8 text-center">
      <div className="max-w-sm text-neutral-400">
        <h1 className="mb-2 text-[16px] font-semibold text-neutral-100">
          Arca
        </h1>
        <p className="text-[13px] leading-relaxed">
          This UI talks to a local Rust backend and must run inside the desktop
          app. Start it with <code className="text-accent">npm run tauri dev</code>{" "}
          from <code>apps/desktop</code>.
        </p>
      </div>
    </div>
  );
}
