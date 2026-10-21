import { Command } from "cmdk";
import { useState } from "react";
import { useNavigate } from "react-router";
import { ArrowIcon, KeyboardIcon, LogoutIcon, MoonIcon, SunIcon } from "@/components/icons";
import { Kbd } from "@/components/ui";
import { useAuth } from "@/lib/auth";
import { useTheme } from "@/lib/theme";
import { navFor } from "./nav";

interface Props {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onShowShortcuts: () => void;
}

const itemCls =
  "flex h-9 cursor-default items-center gap-3 rounded-sm px-2.5 text-sm text-fg-muted " +
  "data-[selected=true]:bg-surface-3 data-[selected=true]:text-fg";

const groupCls =
  "px-1.5 pb-1 [&_[cmdk-group-heading]]:px-2.5 [&_[cmdk-group-heading]]:pt-3 [&_[cmdk-group-heading]]:pb-1.5 " +
  "[&_[cmdk-group-heading]]:text-2xs [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-[var(--tracking-caps)] " +
  "[&_[cmdk-group-heading]]:text-fg-faint";

export function CommandPalette({ open, onOpenChange, onShowShortcuts }: Props) {
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const { resolved, toggle } = useTheme();

  const [search, setSearch] = useState("");
  const num = /^#?(\d{1,9})$/.exec(search.trim())?.[1];

  const run = (fn: () => void) => () => {
    onOpenChange(false);
    fn();
  };

  return (
    <Command.Dialog
      open={open}
      onOpenChange={onOpenChange}
      label="Command palette"
      loop
      overlayClassName="fixed inset-0 z-40 bg-overlay palette-overlay"
      contentClassName="palette-pop fixed left-1/2 top-[14vh] z-50 w-[min(92vw,36rem)] -translate-x-1/2 overflow-hidden rounded-md border border-border-strong bg-surface-1 shadow-pop"
    >
      <div className="flex items-center gap-3 border-b border-border px-4">
        <Command.Input
          autoFocus
          value={search}
          onValueChange={setSearch}
          placeholder="Jump to a page or run a command…"
          className="h-12 flex-1 bg-transparent text-md text-fg outline-none placeholder:text-fg-faint"
        />
        <Kbd>esc</Kbd>
      </div>
      <Command.List className="max-h-[min(60vh,24rem)] overflow-y-auto overscroll-contain py-1">
        <Command.Empty className="px-4 py-8 text-center text-fg-muted">No matches.</Command.Empty>

        {num ? (
          <Command.Group heading="Open by number" className={groupCls}>
            <Command.Item
              value={`open alert ${num}`}
              keywords={[search]}
              onSelect={run(() => {
                void navigate(`/alerts?view=all&alert=${num}`);
              })}
              className={itemCls}
            >
              <span className="flex-1">Open alert #{num}</span>
              <ArrowIcon className="size-3.5 opacity-50" />
            </Command.Item>
            <Command.Item
              value={`open incident ${num}`}
              keywords={[search]}
              onSelect={run(() => {
                void navigate(`/incidents/${num}`);
              })}
              className={itemCls}
            >
              <span className="flex-1">Open incident #{num}</span>
              <ArrowIcon className="size-3.5 opacity-50" />
            </Command.Item>
          </Command.Group>
        ) : null}

        <Command.Group heading="Go to" className={groupCls}>
          {navFor(user?.role).map((n) => (
            <Command.Item
              key={n.to}
              value={`go ${n.label}`}
              keywords={n.keywords ?? []}
              onSelect={run(() => {
                void navigate(n.to);
              })}
              className={itemCls}
            >
              <n.icon className="size-4" />
              <span className="flex-1">{n.label}</span>
              <ArrowIcon className="size-3.5 opacity-50" />
            </Command.Item>
          ))}
        </Command.Group>

        <Command.Group heading="Actions" className={groupCls}>
          <Command.Item
            value="toggle theme"
            keywords={["dark", "light", "appearance"]}
            onSelect={run(toggle)}
            className={itemCls}
          >
            {resolved === "dark" ? <SunIcon className="size-4" /> : <MoonIcon className="size-4" />}
            <span className="flex-1">Switch to {resolved === "dark" ? "light" : "dark"} theme</span>
          </Command.Item>
          <Command.Item
            value="keyboard shortcuts"
            keywords={["help", "keys", "?"]}
            onSelect={run(onShowShortcuts)}
            className={itemCls}
          >
            <KeyboardIcon className="size-4" />
            <span className="flex-1">Keyboard shortcuts</span>
            <Kbd>?</Kbd>
          </Command.Item>
          <Command.Item
            value="log out"
            keywords={["sign out", "logout"]}
            onSelect={run(() => {
              void logout();
            })}
            className={itemCls}
          >
            <LogoutIcon className="size-4" />
            <span className="flex-1">Log out</span>
          </Command.Item>
        </Command.Group>
      </Command.List>
    </Command.Dialog>
  );
}
