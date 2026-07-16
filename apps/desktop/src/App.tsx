import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import type { UnlistenFn } from "@tauri-apps/api/event";

import {
  api,
  errorMessage,
  isTauri,
  onAutofilled,
  onClipboardCleared,
  onFillConsentRequest,
  onPasskeyChanged,
  onVaultLocked,
  type FillConsent,
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
import { SettingsDialog } from "./components/SettingsDialog";
import { ConsentDialog } from "./components/ConsentDialog";
import { TouchIdBanner } from "./components/TouchIdBanner";
import { Toast } from "./components/Toast";
import { KeyIcon } from "./components/icons";

export default function App() {
  const [status, setStatus] = useState<VaultStatus | null>(null);
  const [items, setItems] = useState<ItemSummary[]>([]);
  const [security, setSecurity] = useState<SecurityIssue[]>([]);
  const [category, setCategory] = useState<CategoryId>("all");
  const [search, setSearch] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<ItemDetail | null>(null);
  const [editing, setEditing] = useState<{ id: string | null } | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [consent, setConsent] = useState<FillConsent | null>(null);
  const [toast, setToast] = useState<string | null>(null);

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
        setSelectedId(null);
        setDetail(null);
        setItems([]);
        setSecurity([]);
        void refreshStatus();
      }),
      onClipboardCleared(() => setToast("Clipboard cleared")),
      onAutofilled((what) => setToast(`Autofilled ${what}`)),
      onFillConsentRequest((req) => setConsent(req)),
      onPasskeyChanged((rp, kind) => {
        if (kind === "created") {
          setToast(`Passkey saved for ${rp}`);
          void loadItems(); // a new passkey was written via the browser bridge
        } else {
          setToast(`Signed in to ${rp} with passkey`);
        }
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
    for (const s of security) m.set(s.id, s.issues);
    return m;
  }, [security]);

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
        <LockScreen status={status} onUnlocked={refreshStatus} />
      </Shell>
    );
  }

  const categoryLabel =
    CATEGORIES.find((c) => c.id === category)?.label ?? "All";
  const emptyHint =
    category === "wifi"
      ? "Coming in a later phase."
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
          }}
          search={search}
          onSearch={setSearch}
          onLock={handleLock}
          onOpenSettings={() => setSettingsOpen(true)}
        />
        <EntryList
          title={categoryLabel}
          items={visible}
          selectedId={selectedId}
          onSelect={setSelectedId}
          onAdd={() => setEditing({ id: null })}
          emptyHint={emptyHint}
          issuesById={category === "security" ? issuesById : undefined}
        />
        {detail ? (
          <DetailPane
            detail={detail}
            onEdit={() => setEditing({ id: detail.id })}
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
      {editing && (
        <EditDialog
          itemId={editing.id}
          onClose={() => setEditing(null)}
          onSaved={handleSaved}
        />
      )}
      {consent && (
        <ConsentDialog
          request={consent}
          onResolved={() => setConsent(null)}
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
