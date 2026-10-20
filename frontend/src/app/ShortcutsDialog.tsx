import { Dialog, Kbd } from "@/components/ui";
import { modKeyLabel } from "@/lib/hotkeys";

/** Lists only shortcuts that exist today; grows as features land. */
export const SHORTCUTS: { keys: string[]; label: string }[] = [
  { keys: [modKeyLabel, "K"], label: "Open command palette" },
  { keys: ["?"], label: "Show keyboard shortcuts" },
  { keys: ["Esc"], label: "Close palette, dialog or panel" },
];

export function ShortcutsDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  return (
    <Dialog open={open} onClose={onClose} title="Keyboard shortcuts">
      <ul className="flex flex-col divide-y divide-border">
        {SHORTCUTS.map((s) => (
          <li key={s.label} className="flex items-center justify-between py-2.5">
            <span className="text-fg-muted">{s.label}</span>
            <span className="flex gap-1">
              {s.keys.map((k) => (
                <Kbd key={k}>{k}</Kbd>
              ))}
            </span>
          </li>
        ))}
      </ul>
    </Dialog>
  );
}
