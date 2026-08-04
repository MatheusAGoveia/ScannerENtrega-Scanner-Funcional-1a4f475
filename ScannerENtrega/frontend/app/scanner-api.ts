export interface AuthorizedRange {
  id: string;
  name: string;
  cidr: string;
  address_count: number;
  environment: string;
  owner: string;
  description?: string | null;
  authorization_reference: string;
  enabled: boolean;
  allow_public: boolean;
  created_at: string;
  updated_at: string;
}

export interface ScannerProfile {
  id: string;
  slug: string;
  name: string;
  description: string;
  discovery_enabled: boolean;
  service_detection_enabled: boolean;
  vulnerability_detection_enabled: boolean;
  tcp_ports: string;
  udp_ports: string;
  active: boolean;
}

export interface ScanSchedule {
  id: string;
  name: string;
  range_id: string;
  profile_id: string;
  cron_expression: string;
  timezone_name: string;
  max_duration_minutes: number;
  intensity: string;
  sync_zabbix: boolean;
  enabled: boolean;
  next_run_at?: string | null;
  last_run_at?: string | null;
  justification: string;
  created_by: string;
  created_at: string;
  range_name?: string | null;
  cidr?: string | null;
  profile_name?: string | null;
}

export interface EngineRun {
  engine: string;
  status: string;
  started_at?: string | null;
  finished_at?: string | null;
  result_count: number;
  error_message?: string | null;
}

export interface ScanExecution {
  id: string;
  schedule_id?: string | null;
  range_id: string;
  profile_id: string;
  trigger_type: string;
  status: string;
  requested_by: string;
  justification: string;
  cancellation_requested: boolean;
  queued_at: string;
  started_at?: string | null;
  heartbeat_at?: string | null;
  finished_at?: string | null;
  active_ips: number;
  services_discovered: number;
  vulnerabilities_discovered: number;
  critical_vulnerabilities: number;
  error_summary?: string | null;
  range_name?: string | null;
  cidr?: string | null;
  profile_name?: string | null;
  engine_runs: EngineRun[];
}

export interface DiscoveredService {
  id: string;
  protocol: string;
  port: number;
  state: string;
  service_name?: string | null;
  product?: string | null;
  version?: string | null;
  banner?: string | null;
  tls_details?: string | null;
  last_seen_at: string;
}

export interface DiscoveredAsset {
  id: string;
  range_id: string;
  ip_address: string;
  hostname?: string | null;
  state: string;
  os_name?: string | null;
  municipal_service?: string | null;
  zabbix_status: string;
  first_seen_at: string;
  last_seen_at: string;
  services: DiscoveredService[];
  open_findings: number;
  highest_severity?: string | null;
}

export interface VulnerabilityFinding {
  id: string;
  asset_id: string;
  service_id?: string | null;
  engine: string;
  template_id: string;
  name: string;
  severity: string;
  matched_at: string;
  description?: string | null;
  reference?: string | null;
  status: string;
  first_seen_at: string;
  last_seen_at: string;
  ip_address?: string | null;
  service?: string | null;
}

export interface Summary {
  authorized_ips: number;
  ranges_count: number;
  active_ips: number;
  new_assets_30d: number;
  services: number;
  unlinked_assets: number;
  open_findings: number;
  critical_findings: number;
  coverage: Array<{
    id: string;
    name: string;
    cidr: string;
    coverage_percent: number;
    active_assets: number;
    services: number;
    critical_findings: number;
  }>;
  next_runs: ScanSchedule[];
  zabbix_configured: boolean;
  zabbix_pending: number;
}

export interface EngineStatus {
  name: string;
  available: boolean;
  version?: string | null;
  detail: string;
}

export interface ImportPreview {
  batch_id: string;
  filename: string;
  total: number;
  valid: number;
  invalid: number;
  duplicates: number;
  overlaps: number;
  expires_at: string;
  items: Array<{
    original: string;
    normalized?: string | null;
    valid: boolean;
    duplicate: boolean;
    overlap_with?: string | null;
    error?: string | null;
  }>;
}

export class ScannerApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export async function scannerRequest<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api/scanner/${path}`, {
    ...init,
    headers: {
      ...(init?.body instanceof FormData ? {} : { "Content-Type": "application/json" }),
      ...init?.headers,
    },
    cache: "no-store",
  });
  if (!response.ok) {
    let message = `Falha na API (${response.status}).`;
    try {
      const body = await response.json();
      if (typeof body.detail === "string") message = body.detail;
    } catch {}
    throw new ScannerApiError(response.status, message);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export function formatDate(value?: string | null): string {
  if (!value) return "—";
  return new Intl.DateTimeFormat("pt-BR", {
    dateStyle: "short",
    timeStyle: "short",
    timeZone: "America/Sao_Paulo",
  }).format(new Date(value));
}

export function shortId(id: string, prefix: string): string {
  return `${prefix}-${id.replaceAll("-", "").slice(0, 8).toUpperCase()}`;
}
