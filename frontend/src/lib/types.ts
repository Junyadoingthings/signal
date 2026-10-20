export type Role = "admin" | "analyst";
export type Severity = "low" | "medium" | "high" | "critical";

export interface User {
  id: number;
  email: string;
  display_name: string;
  role: Role;
  is_active: boolean;
  created_at: string;
  last_login_at: string | null;
}

export interface Me {
  user: User;
  csrf_token: string;
  session_expires_at: string;
}

export interface AuditEntry {
  id: number;
  ts: string;
  actor_id: number | null;
  actor_email: string | null;
  action: string;
  target_type: string | null;
  target_id: string | null;
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
  ip: string | null;
}

export interface AuditPage {
  items: AuditEntry[];
  next_before_id: number | null;
}

export interface SystemStatus {
  events_total: number;
  events_last_24h: number;
  unparsed_total: number;
  alerts_open: number;
  incidents_open: number;
  rules_enabled: number;
  last_event_at: string | null;
  last_ingest_at: string | null;
}
