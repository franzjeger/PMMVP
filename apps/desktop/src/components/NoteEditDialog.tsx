import { useEffect, useState } from "react";
import { api, errorMessage } from "../lib/api";
import { NoteIcon } from "./icons";

/** Create or edit a secure note: a title plus a free-form encrypted body. */
export function NoteEditDialog({
  itemId,
  onClose,
  onSaved,
}: {
  itemId: string | null;
  onClose: () => void;
  onSaved: (id: string) => void;
}) {
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [loading, setLoading] = useState(itemId !== null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (itemId === null) {
      setLoading(false);
      return;
    }
    let alive = true;
    (async () => {
      try {
        const d = await api.getItem(itemId);
        if (!alive) return;
        setTitle(d.title);
        setBody(d.notes); // the note body rides in `notes`
      } catch (e) {
        if (alive) setError(errorMessage(e));
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => {
      alive = false;
    };
  }, [itemId]);

  const save = async () => {
    if (!title.trim() && !body.trim()) {
      setError("Add a title or some text.");
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const id = await api.upsertSecureNote({ id: itemId, title, body });
      onSaved(id);
    } catch (e) {
      setError(errorMessage(e));
      setSaving(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-40 flex items-center justify-center bg-black/50 p-6 backdrop-blur-sm"
      onMouseDown={(e) => e.target === e.currentTarget && onClose()}
    >
      <div className="flex max-h-[85vh] w-full max-w-lg flex-col rounded-2xl border border-hairline bg-panel shadow-2xl">
        <div className="flex items-center gap-2 border-b border-hairline px-5 py-3.5">
          <NoteIcon className="h-5 w-5 text-accent" />
          <h2 className="text-[15px] font-semibold text-neutral-100">
            {itemId === null ? "New note" : "Edit note"}
          </h2>
        </div>

        {loading ? (
          <div className="px-5 py-10 text-center text-[13px] text-neutral-500">
            Loading…
          </div>
        ) : (
          <div className="flex min-h-0 flex-1 flex-col gap-3 px-5 py-4">
            <input
              value={title}
              autoFocus
              placeholder="Title"
              onChange={(e) => setTitle(e.target.value)}
              className="w-full rounded-lg bg-fill/5 px-3 py-2 text-[14px] font-medium text-neutral-100 outline-none ring-1 ring-line/10 placeholder-neutral-600 focus:ring-accent/60"
              spellCheck={false}
            />
            <textarea
              value={body}
              placeholder="Write anything — recovery codes, secrets, notes… encrypted like everything else."
              onChange={(e) => setBody(e.target.value)}
              className="min-h-[220px] flex-1 resize-none rounded-lg bg-fill/5 px-3 py-2 text-[13px] leading-relaxed text-neutral-100 outline-none ring-1 ring-line/10 placeholder-neutral-600 focus:ring-accent/60"
            />
            {error && <p className="text-[12px] text-red-400">{error}</p>}
          </div>
        )}

        <div className="flex shrink-0 justify-end gap-2 border-t border-hairline px-5 py-3">
          <button
            onClick={onClose}
            className="rounded-lg px-4 py-1.5 text-[13px] text-neutral-300 hover:bg-fill/5"
          >
            Cancel
          </button>
          <button
            onClick={() => void save()}
            disabled={saving || loading}
            className="rounded-lg bg-accent px-4 py-1.5 text-[13px] font-medium text-white hover:bg-accent/90 disabled:opacity-60"
          >
            {saving ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}
