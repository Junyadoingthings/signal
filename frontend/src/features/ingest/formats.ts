import type { Batch, IngestFormat } from "@/lib/types";

export const FORMAT_LABEL: Record<IngestFormat, string> = {
  linux_auth: "Linux auth (syslog)",
  evtx: "Windows EVTX",
  windows_json: "Windows / Sysmon JSON",
  web_access: "Web access log",
  wazuh: "Wazuh alerts",
  generic_jsonl: "Generic JSON Lines",
};

export const FORMAT_OPTIONS: { value: "auto" | IngestFormat; label: string; hint: string }[] = [
  { value: "auto", label: "Auto-detect", hint: "Detected from content, not the file extension." },
  {
    value: "linux_auth",
    label: FORMAT_LABEL.linux_auth,
    hint: "auth.log / secure: sshd, sudo, su, useradd, usermod.",
  },
  {
    value: "evtx",
    label: FORMAT_LABEL.evtx,
    hint: "Security and Sysmon .evtx exports. Parsed record by record.",
  },
  {
    value: "windows_json",
    label: FORMAT_LABEL.windows_json,
    hint: "evtx_dump JSON or PowerShell Get-WinEvent | ConvertTo-Json.",
  },
  {
    value: "web_access",
    label: FORMAT_LABEL.web_access,
    hint: "nginx / Apache Common or Combined format.",
  },
  {
    value: "wazuh",
    label: FORMAT_LABEL.wazuh,
    hint: "alerts.json, one alert per line. Windows/Sysmon data is unpacked.",
  },
  {
    value: "generic_jsonl",
    label: FORMAT_LABEL.generic_jsonl,
    hint: "Any JSON Lines file. You map its fields below.",
  },
];

/** Schema fields a generic mapping may target, in display order. */
export const MAPPABLE_FIELDS = [
  "timestamp",
  "host",
  "user",
  "src_ip",
  "dst_ip",
  "src_port",
  "dst_port",
  "process_name",
  "process_cmdline",
  "parent_process",
  "event_code",
  "action",
  "outcome",
  "dns_query",
  "url",
  "http_status",
  "user_agent",
] as const;

export function batchName(b: Batch): string {
  return b.filename ?? (b.kind === "live" ? "live stream" : "upload");
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 ** 2).toFixed(1)} MB`;
}
