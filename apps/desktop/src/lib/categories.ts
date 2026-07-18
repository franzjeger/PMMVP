import type { ItemSummary } from "./api";

export type CategoryId =
  | "all"
  | "passkeys"
  | "codes"
  | "wifi"
  | "sshKeys"
  | "security"
  | "deleted";

export interface CategoryDef {
  id: CategoryId;
  label: string;
}

export const CATEGORIES: CategoryDef[] = [
  { id: "all", label: "All" },
  { id: "passkeys", label: "Passkeys" },
  { id: "codes", label: "Codes" },
  { id: "wifi", label: "Wi-Fi" },
  { id: "sshKeys", label: "SSH Keys" },
  { id: "security", label: "Security" },
  { id: "deleted", label: "Deleted" },
];

/** Items shown for a category. Wi-Fi/Security are Phase-2 stubs. */
export function filterByCategory(
  items: ItemSummary[],
  cat: CategoryId,
): ItemSummary[] {
  switch (cat) {
    case "all":
      return items.filter((i) => !i.isDeleted);
    case "passkeys":
      return items.filter((i) => !i.isDeleted && i.kind === "passkey");
    case "codes":
      return items.filter((i) => !i.isDeleted && i.hasTotp);
    case "wifi":
      return items.filter((i) => !i.isDeleted && i.kind === "wifi");
    case "sshKeys":
      return items.filter((i) => !i.isDeleted && i.kind === "sshKey");
    case "security":
      return []; // TODO(phase-2): weak / reused / breached audit
    case "deleted":
      return items.filter((i) => i.isDeleted);
  }
}

export function categoryCount(items: ItemSummary[], cat: CategoryId): number {
  return filterByCategory(items, cat).length;
}
