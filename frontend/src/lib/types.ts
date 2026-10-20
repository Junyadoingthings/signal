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

export type IngestFormat =
  "evtx" | "windows_json" | "linux_auth" | "web_access" | "wazuh" | "generic_jsonl";

export interface Batch {
  id: number;
  source_type: IngestFormat;
  kind: "upload" | "live";
  filename: string | null;
  default_host: string | null;
  size_bytes: number;
  status: "pending" | "running" | "done" | "failed" | "live";
  parsed_count: number;
  unparsed_count: number;
  duplicate_count: number;
  tz_assumption: string | null;
  year_assumption: number | null;
  error: string | null;
  created_at: string;
  finished_at: string | null;
}

export interface Page<T> {
  items: T[];
  next_before_id: number | null;
}

export interface UnparsedRecord {
  id: number;
  batch_id: number | null;
  line_no: number | null;
  raw: string;
  reason: string;
  created_at: string;
}

export interface EventRecord {
  id: number;
  timestamp: string;
  ingested_at: string;
  batch_id: number | null;
  source_type: string;
  host: string | null;
  user: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  process_name: string | null;
  process_cmdline: string | null;
  parent_process: string | null;
  event_code: string | null;
  action: string | null;
  outcome: "success" | "failure" | "unknown";
  dns_query: string | null;
  url: string | null;
  http_status: number | null;
  user_agent: string | null;
  raw: string;
  tags: string[];
  extra: Record<string, unknown>;
}

export interface IngestSettings {
  syslog_timezone: string;
  syslog_year: number | null;
  max_upload_bytes: number;
}

export interface IngestToken {
  id: number;
  name: string;
  prefix: string;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

export interface IngestTokenCreated extends IngestToken {
  token: string;
}
