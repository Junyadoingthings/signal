import type { ComponentType, SVGProps } from "react";
import { AuditIcon, OverviewIcon, UsersIcon } from "@/components/icons";
import type { Role } from "@/lib/types";

export interface NavItem {
  to: string;
  label: string;
  icon: ComponentType<SVGProps<SVGSVGElement>>;
  /** Shown in the palette to help fuzzy matching. */
  keywords?: string[];
  roles?: Role[];
}

/** Single source of truth for the rail and the command palette. */
export const NAV: NavItem[] = [
  { to: "/", label: "Overview", icon: OverviewIcon, keywords: ["dashboard", "home", "status"] },
  {
    to: "/admin/users",
    label: "Users",
    icon: UsersIcon,
    keywords: ["accounts", "roles", "team"],
    roles: ["admin"],
  },
  {
    to: "/admin/audit",
    label: "Audit log",
    icon: AuditIcon,
    keywords: ["history", "trail", "who changed"],
    roles: ["admin"],
  },
];

export function navFor(role: Role | undefined): NavItem[] {
  return NAV.filter((n) => !n.roles || (role !== undefined && n.roles.includes(role)));
}
