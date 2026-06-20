import { tileColor } from "../lib/format";

/** A colored rounded-square letter tile, as used for each entry. */
export function Tile({
  letter,
  seed,
  size = 34,
}: {
  letter: string;
  seed: string;
  size?: number;
}) {
  const bg = tileColor(seed);
  return (
    <div
      className="flex shrink-0 items-center justify-center rounded-[22%] font-semibold text-white shadow-sm"
      style={{
        width: size,
        height: size,
        background: bg,
        fontSize: size * 0.5,
      }}
      aria-hidden
    >
      {letter}
    </div>
  );
}
