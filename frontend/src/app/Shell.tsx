import { clsx } from "clsx";
import { Suspense, useState } from "react";
import { NavLink, Outlet, useLocation, useMatches } from "react-router";
import { LogoutIcon, MoonIcon, SearchIcon, SunIcon } from "@/components/icons";
import { Kbd, LogoMark } from "@/components/ui";
import { useAuth } from "@/lib/auth";
import { modKeyLabel, useHotkey } from "@/lib/hotkeys";
import { useLive } from "@/lib/live";
import { useTheme } from "@/lib/theme";
import { CommandPalette } from "./CommandPalette";
import { NAV, navFor } from "./nav";
import { ShortcutsDialog } from "./ShortcutsDialog";

export function Shell() {
  const { user, logout } = useAuth();
  const { resolved, toggle } = useTheme();
  const { connected } = useLive();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const location = useLocation();

  useHotkey(
    "k",
    () => {
      setPaletteOpen((o) => !o);
    },
    { mod: true, allowInInputs: true },
  );
  useHotkey("?", () => {
    setShortcutsOpen(true);
  });

  const fullBleed = useMatches().some(
    (m) => (m.handle as { fullBleed?: boolean } | undefined)?.fullBleed,
  );
  const items = navFor(user?.role);
  const current = NAV.find((n) =>
    n.to === "/" ? location.pathname === "/" : location.pathname.startsWith(n.to),
  );

  return (
    <div className="flex h-full">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded-sm focus:bg-surface-2 focus:px-3 focus:py-2"
      >
        Skip to content
      </a>

      {/* Rail */}
      <nav
        aria-label="Primary"
        className="flex w-[var(--rail-width)] shrink-0 flex-col items-center border-r border-border bg-bg py-3"
      >
        <NavLink
          to="/"
          aria-label="SIGNAL home"
          className="mb-5 grid size-9 place-items-center text-fg"
        >
          <LogoMark className="size-6" />
        </NavLink>
        <ul className="flex flex-col gap-1">
          {items.map((n) => (
            <li key={n.to}>
              <NavLink
                to={n.to}
                end={n.to === "/"}
                title={n.label}
                aria-label={n.label}
                className={({ isActive }) =>
                  clsx(
                    "relative grid size-9 place-items-center rounded-sm transition-colors duration-[var(--dur-fast)]",
                    isActive
                      ? "bg-surface-2 text-fg"
                      : "text-fg-faint hover:bg-surface-1 hover:text-fg-muted",
                  )
                }
              >
                {({ isActive }) => (
                  <>
                    {isActive ? (
                      <span
                        aria-hidden="true"
                        className="absolute top-2 bottom-2 -left-[0.6875rem] w-px bg-fg"
                      />
                    ) : null}
                    <n.icon className="size-4" />
                  </>
                )}
              </NavLink>
            </li>
          ))}
        </ul>
        <div className="mt-auto flex flex-col items-center gap-1">
          <button
            type="button"
            onClick={toggle}
            title={`Switch to ${resolved === "dark" ? "light" : "dark"} theme`}
            aria-label={`Switch to ${resolved === "dark" ? "light" : "dark"} theme`}
            className="grid size-9 place-items-center rounded-sm text-fg-faint hover:bg-surface-1 hover:text-fg-muted"
          >
            {resolved === "dark" ? <SunIcon className="size-4" /> : <MoonIcon className="size-4" />}
          </button>
          <button
            type="button"
            onClick={() => {
              void logout();
            }}
            title="Log out"
            aria-label="Log out"
            className="grid size-9 place-items-center rounded-sm text-fg-faint hover:bg-surface-1 hover:text-fg-muted"
          >
            <LogoutIcon className="size-4" />
          </button>
        </div>
      </nav>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-[var(--topbar-height)] shrink-0 items-center gap-4 border-b border-border px-4 sm:px-6">
          <p className="shrink-0 text-sm">
            <span className="font-semibold tracking-[var(--tracking-tight)]">signal</span>
            {current ? (
              <>
                <span className="px-2 text-fg-faint">/</span>
                <span className="text-fg-muted">{current.label}</span>
              </>
            ) : null}
          </p>

          <button
            type="button"
            onClick={() => {
              setPaletteOpen(true);
            }}
            className="ml-auto flex h-8 w-full min-w-0 max-w-72 items-center gap-2 rounded-sm border border-border bg-surface-1 px-2.5 text-fg-faint transition-colors hover:border-border-strong hover:text-fg-muted"
          >
            <SearchIcon className="size-3.5" />
            <span className="flex-1 truncate text-left">Search or jump to…</span>
            <span className="hidden gap-0.5 sm:flex">
              <Kbd>{modKeyLabel}</Kbd>
              <Kbd>K</Kbd>
            </span>
          </button>

          <span
            className="hidden items-center gap-1.5 text-2xs text-fg-faint sm:inline-flex"
            title={connected ? "Receiving live updates" : "Live updates disconnected; retrying"}
          >
            <span
              aria-hidden="true"
              className={clsx("size-1.5 rounded-full", connected ? "bg-ok" : "bg-fg-faint")}
            />
            {connected ? "live" : "offline"}
          </span>
          <div className="hidden items-center gap-2.5 md:flex" title={user?.email}>
            <span
              aria-hidden="true"
              className="grid size-7 place-items-center rounded-full border border-border bg-surface-2 text-2xs font-semibold uppercase text-fg-muted"
            >
              {user?.display_name.slice(0, 2)}
            </span>
            <span className="flex flex-col leading-tight">
              <span className="text-xs">{user?.display_name}</span>
              <span className="text-2xs text-fg-faint capitalize">{user?.role}</span>
            </span>
          </div>
        </header>

        <main
          id="main"
          tabIndex={-1}
          className={clsx(
            "min-h-0 flex-1 outline-none",
            fullBleed ? "overflow-hidden" : "overflow-y-auto px-4 py-6 sm:px-8 sm:py-8",
          )}
        >
          <Suspense
            fallback={
              <div className="p-8" role="status" aria-busy="true">
                <span className="sr-only">Loading page</span>
                <div className="skeleton h-7 w-48" />
                <div className="skeleton mt-4 h-40 w-full max-w-3xl" />
              </div>
            }
          >
            <Outlet />
          </Suspense>
        </main>
      </div>

      <CommandPalette
        open={paletteOpen}
        onOpenChange={setPaletteOpen}
        onShowShortcuts={() => {
          setShortcutsOpen(true);
        }}
      />
      <ShortcutsDialog
        open={shortcutsOpen}
        onClose={() => {
          setShortcutsOpen(false);
        }}
      />
    </div>
  );
}
