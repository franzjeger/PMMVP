import type { ItemSummary, SecurityTag } from "../lib/api";
import { ClockIcon, PasskeyIcon, PlusIcon } from "./icons";
import { Tile } from "./Tile";

const ISSUE_LABEL: Record<SecurityTag, string> = {
  weak: "Weak",
  reused: "Reused",
};

export function EntryList({
  title,
  items,
  selectedId,
  onSelect,
  onAdd,
  emptyHint,
  issuesById,
}: {
  title: string;
  items: ItemSummary[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  onAdd: () => void;
  emptyHint?: string;
  /** When present (Security view), renders issue badges per item. */
  issuesById?: Map<string, SecurityTag[]>;
}) {
  return (
    <div className="flex w-[340px] shrink-0 flex-col border-r border-hairline bg-panel">
      <div className="flex h-12 items-center justify-between px-4">
        <h2 className="text-[15px] font-bold text-neutral-100">{title}</h2>
        <button
          onClick={onAdd}
          className="rounded-md p-1 text-accent hover:bg-white/5"
          title="Add item"
        >
          <PlusIcon className="h-5 w-5" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto px-2 pb-2">
        {items.length === 0 ? (
          <p className="px-3 py-8 text-center text-[13px] text-neutral-500">
            {emptyHint ?? "No items"}
          </p>
        ) : (
          items.map((item) => {
            const isSel = item.id === selectedId;
            return (
              <button
                key={item.id}
                onClick={() => onSelect(item.id)}
                className={`flex w-full items-center gap-3 rounded-lg px-2 py-2 text-left transition-colors ${
                  isSel ? "bg-accent/90" : "hover:bg-white/5"
                }`}
              >
                <Tile letter={item.letter} seed={item.title || item.id} />
                <div className="min-w-0 flex-1">
                  <div
                    className={`truncate text-[13px] font-semibold ${
                      isSel ? "text-white" : "text-neutral-100"
                    }`}
                  >
                    {item.title || "Untitled"}
                  </div>
                  {item.subtitle && (
                    <div
                      className={`truncate text-[12px] ${
                        isSel ? "text-white/80" : "text-neutral-500"
                      }`}
                    >
                      {item.subtitle}
                    </div>
                  )}
                  {issuesById && issuesById.get(item.id) && (
                    <div className="mt-1 flex flex-wrap gap-1">
                      {issuesById.get(item.id)!.map((tag) => (
                        <span
                          key={tag}
                          className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${
                            isSel
                              ? "bg-white/20 text-white"
                              : "bg-amber-500/15 text-amber-400"
                          }`}
                        >
                          {ISSUE_LABEL[tag]}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
                <div
                  className={`flex items-center gap-1.5 ${
                    isSel ? "text-white/80" : "text-neutral-600"
                  }`}
                >
                  {item.hasTotp && <ClockIcon className="h-4 w-4" />}
                  {item.kind === "passkey" && (
                    <PasskeyIcon className="h-4 w-4" />
                  )}
                </div>
              </button>
            );
          })
        )}
      </div>
    </div>
  );
}
