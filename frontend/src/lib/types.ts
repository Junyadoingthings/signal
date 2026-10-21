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

export interface TechniqueRef {
  id: string;
  name: string | null;
  url: string | null;
}

export interface RuleSummary {
  id: string;
  title: string;
  severity: Severity;
  enabled: boolean;
  logic_type: "match" | "threshold" | "sequence" | "first_seen" | "unknown";
  primary_tactic: string | null;
  techniques: TechniqueRef[];
  hit_count: number;
  last_fired_at: string | null;
  tags: string[];
}

export interface RuleDetail extends RuleSummary {
  description: string;
  false_positives: string[];
  references: string[];
  yaml: string;
  updated_at: string;
}

export interface MatchHit {
  field: string;
  op: string;
  expected: unknown;
  actual: unknown;
}

export interface Alert {
  id: number;
  rule_id: string;
  severity: Severity;
  status: "new" | "investigating" | "closed";
  verdict: string | null;
  host: string | null;
  user: string | null;
  src_ip: string | null;
  group_key: string;
  event_count: number;
  first_event_at: string;
  last_event_at: string;
  created_at: string;
  match_context: { type?: string; matched?: MatchHit[] } & Record<string, unknown>;
  incident_id: number | null;
}

export interface AttackTactic {
  id: string;
  shortname: string;
  name: string;
  url: string;
  rule_count: number;
}

export interface AttackMatrix {
  version: string;
  tactics: AttackTactic[];
}

export interface DetectionSettings {
  business_timezone: string;
  business_start: string;
  business_end: string;
  business_days: number[];
}

export type AlertStatus = "new" | "investigating" | "closed";
export type Verdict = "true_positive" | "false_positive" | "benign_true_positive";

export interface AlertRow extends Alert {
  rule_title: string;
  tactic: string | null;
  assignee_id: number | null;
  assignee_name: string | null;
  acknowledged_at: string | null;
  closed_at: string | null;
}

export interface AlertList {
  items: AlertRow[];
  total: number;
  offset: number;
  limit: number;
}

export interface AlertDetail {
  alert: AlertRow;
  rule: {
    id: string;
    title: string;
    description: string;
    severity: Severity;
    logic_type: string;
    primary_tactic: string | null;
    techniques: TechniqueRef[];
    false_positives: string[];
  };
  events: EventRecord[];
  events_total: number;
}

export interface Note {
  id: number;
  author_id: number;
  author_name: string;
  markdown: string;
  created_at: string;
}

export interface HistoryEntry {
  kind: "audit" | "note";
  ts: string;
  actor: string | null;
  action?: string | null;
  before?: Record<string, unknown> | null;
  after?: Record<string, unknown> | null;
  note?: Note | null;
}

export interface Incident {
  id: number;
  title: string;
  score: number;
  severity: Severity;
  status: AlertStatus;
  verdict: Verdict | null;
  assignee_id: number | null;
  tactics: string[];
  entities: { host?: string[]; user?: string[]; src_ip?: string[] };
  alert_count: number;
  first_event_at: string;
  last_event_at: string;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
}

export interface StoryStep {
  alert_id: number;
  rule_id: string;
  title: string;
  tactic: string | null;
  techniques: string[];
  severity: Severity;
  time: string;
  status: AlertStatus;
}

export interface IncidentDetail {
  incident: Incident;
  alerts: AlertRow[];
  storyline: StoryStep[];
}

export interface UserBrief {
  id: number;
  display_name: string;
  role: Role;
}

export interface TriagePatch {
  status?: AlertStatus;
  verdict?: Verdict;
  assignee_id?: number;
  unassign?: boolean;
}

export interface HuntResult {
  items: EventRecord[];
  total: number;
  offset: number;
  limit: number;
}

export interface Bucket {
  start: string;
  count: number;
  failures: number;
}

export interface Histogram {
  start: string;
  end: string;
  bucket_seconds: number;
  buckets: Bucket[];
  total: number;
}

export interface SavedSearch {
  id: number;
  owner_id: number;
  name: string;
  query: string;
  time_range: string;
  created_at: string;
}

export type EntityType = "host" | "user" | "ip" | "process" | "domain";

export interface GraphNode {
  id: string;
  type: EntityType;
  value: string;
  event_count: number;
  hop: number;
}

export interface GraphEdge {
  source: string;
  target: string;
  relation: string;
  count: number;
}

export interface EntityDetail {
  entity: {
    type: EntityType;
    value: string;
    first_seen: string;
    last_seen: string;
    event_count: number;
  };
  actions: Record<string, number>;
  alerts: AlertRow[];
  incident_ids: number[];
  events: EventRecord[];
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface OverviewData {
  start: string;
  end: string;
  bucket_seconds: number;
  buckets: Bucket[];
  events_total: number;
  markers: { id: number; ts: string; severity: Severity; title: string }[];
  open_incidents: Record<Severity, number>;
  open_alerts: Record<Severity, number>;
  noisy_rules: { rule_id: string; title: string; severity: Severity; count: number }[];
  top_entities: { type: EntityType; value: string; count: number; top_severity: Severity }[];
  fired_tactics: Record<string, number>;
  mttr_seconds: number | null;
  closed_count: number;
  verdicts: Record<string, number>;
}
