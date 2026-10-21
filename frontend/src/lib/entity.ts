import type { EntityType } from "./types";

export function entityPath(type: EntityType, value: string): string {
  return `/entities/${type}?value=${encodeURIComponent(value)}`;
}

export function huntQueryFor(type: EntityType, value: string): string {
  const v = /[\s"():]/.test(value) ? `"${value.replaceAll('"', '\\"')}"` : value;
  switch (type) {
    case "host":
      return `host:${v}`;
    case "user":
      return `user:${v}`;
    case "ip":
      return `ip:${v}`;
    case "process":
      return `process:${v}`;
    case "domain":
      return `dns:*${v}`;
  }
}

export const ENTITY_LABEL: Record<EntityType, string> = {
  host: "Host",
  user: "User",
  ip: "IP address",
  process: "Process",
  domain: "Domain",
};
