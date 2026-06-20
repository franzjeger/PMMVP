import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import type { UnlistenFn } from "@tauri-apps/api/event";

import {
  api,
  errorMessage,
  isTauri,
  onClipboardCleared,
  onVaultLocked,
  type ItemDetail,
  type ItemSummary,
  type VaultStatus,
} from "./lib/api";
import {
  CATEGORIES,
  filterByCategory,
  type CategoryId,
} from "./lib/categories";

import { TitleBar } from "./components/TitleBar";
import { Sidebar } from "./components/Sidebar";
import { EntryList } from "./components/EntryList";
import { DetailPane } from "./components/DetailPane";
import { LockScreen } from "./components/LockScreen";
import { EditDialog } from "./components/EditDialog";
import { Toast } from "./components/Toast";
import { KeyIcon } from "./components/icons";

export default function App() {
  const [status, setStatus] = useState<VaultStatus | null>(null);
  const [items, setItems] = useState<ItemSummary[]>([]);
  const [category, setCategory] = useState<CategoryId>("all");
  const [search, setSearch] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<ItemDetail | null>(null);
  const [editing, setEditing] = useState<{ id: string | null } | null>(null);
  const [toast, setToast] = useState<string | null>(null);

  const loadItems = useCallback(async () => {
    try {
      setItems(await api.listItems(true));
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
    else setStatus({ exists: false, unlocked: false, hasQuickUnlock: false, quickUnlockAvailable: false });
  }, [refreshStatus]);

  // Backend-driven auto-lock + clipboard events.
  useEffect(() => {
    const pending: Promise<UnlistenFn>[] = [
      onVaultLocked(() => {
        setSelectedId(null);
        setDetail(null);
        setItems([]);
        void refreshStatus();
      }),
      onClipboardCleared(() => setToast("Clipboard cleared")),
    ];
    return () => {
      pending.forEach((p) => p.then((u) => u()).catch(() => {}));
    };
  }, [refreshStatus]);

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

  const visible = useMemo(() => {
    const byCat = filterByCategory(items, category);
    const q = search.trim().toLowerCase();
    if (!q) return byCat;
    return byCat.filter(
      (i) =>
        i.title.toLowerCase().includes(q) ||
        i.subtitle.toLowerCase().includes(q),
    );
  }, [items, category, search]);

  // Keep a sensible selection as the visible list changes.
  useEffect(() => {
    if (visible.length === 0) {
      setSelectedId(null);
      return;
    }
    if (!selectedId || !visible.some((i) => i.id === selectedId)) {
      setSelectedId(visible[0].id);
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
    category === "wifi" || category === "security"
      ? "Coming in a later phase."
      : category === "deleted"
        ? "Trash is empty."
        : "No items yet — click + to add one.";

  return (
    <Shell>
      <div className="flex flex-1 overflow-hidden">
        <Sidebar
          items={items}
          active={category}
          onSelect={(c) => {
            setCategory(c);
            setSelectedId(null);
          }}
          search={search}
          onSearch={setSearch}
          onLock={handleLock}
        />
        <EntryList
          title={categoryLabel}
          items={visible}
          selectedId={selectedId}
          onSelect={setSelectedId}
          onAdd={() => setEditing({ id: null })}
          emptyHint={emptyHint}
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

      {editing && (
        <EditDialog
          itemId={editing.id}
          onClose={() => setEditing(null)}
          onSaved={handleSaved}
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
          SYBR Passwords
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
