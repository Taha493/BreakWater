// The gateway admin API (spec sections 5 and 10). The admin key is held in memory by the
// caller and sent as a bearer token; nothing here persists it.

export type RangeName = "1h" | "24h" | "7d" | "30d";
export const RANGES: RangeName[] = ["1h", "24h", "7d", "30d"];
export const ATTACK_CLASSES = ["A1", "A2", "A3", "A4"] as const;
export type AttackClass = (typeof ATTACK_CLASSES)[number];

export interface Stats {
  range: RangeName;
  since: string;
  until: string;
  bucket_seconds: number;
  totals: {
    events: number;
    requests: number;
    blocked: number;
    redacted: number;
    allowed: number;
    block_rate: number | null;
    judge_calls: number;
    by_direction: Record<string, number>;
    by_action: Record<string, number>;
  };
  latency_ms: { p50: number | null; p95: number | null };
  by_class: Record<AttackClass, { blocked: number; redacted: number }>;
  series: { ts: string; blocked: Record<AttackClass, number>; redacted: Record<AttackClass, number> }[];
}

export interface EventRow {
  id: string;
  request_id: string;
  ts: string;
  app: string | null;
  session: string | null;
  direction: string;
  role: string;
  action: string;
  risk_score: number;
  latency_ms: number;
  judge_used: boolean;
  upstream_model: string | null;
  ruleset_version: string;
  attack_classes: string[];
  detectors: string[];
  excerpt_redacted: string;
}

export interface FindingRow {
  detector: string;
  attack_class: string;
  severity: string;
  score: number;
  rule_id: string | null;
  reason: string;
  span: [number, number] | null;
  layer: number;
  message_index: number | null;
}

export interface EventDetail extends EventRow {
  findings: FindingRow[];
}

export interface EventPage {
  events: EventRow[];
  next_cursor: string | null;
}

export interface DocumentRow {
  id: string;
  doc_id: string;
  source: string | null;
  trust_level: string;
  status: string;
  risk_score: number;
  ruleset_version: string;
  created_at: string;
  chunks: number;
  quarantined_chunks: number;
}

export interface Documents {
  counts: Record<string, number>;
  top_risky: DocumentRow[];
  recent: DocumentRow[];
}

export interface QuarantineEntry {
  id: string;
  doc_id: string;
  source: string | null;
  trust_level: string;
  chunk_id: string;
  chunk_index: number;
  hidden_kind: string | null;
  risk_score: number;
  reason: string;
  excerpt_redacted: string;
  created_at: string;
  decision: string | null;
  reviewed_by: string | null;
  reviewed_at: string | null;
}

export interface PolicyVersionInfo {
  id: number;
  created_at: string;
  created_by: string;
  comment: string | null;
  active: boolean;
}

export interface PolicyVersion extends PolicyVersionInfo {
  content: string;
}

export interface PolicyConfig {
  thresholds: { allow_below: number; judge_band: [number, number]; block_at: number };
  actions: Record<string, Record<string, string>>;
  weights: Record<string, number>;
  judge: { enabled: boolean; timeout_ms: number; max_calls_per_minute: number };
  [key: string]: unknown;
}

export interface ActivePolicy extends PolicyVersion {
  ruleset_version: string;
  config: PolicyConfig;
}

export interface Rate {
  rate: number | null;
  successes: number;
  n: number;
  errors: number;
}

export interface ModeRates {
  unprotected: Rate;
  protected: Rate;
  block_rate: number | null;
}

export interface LayerSummary {
  asr: { overall: Rate; by_category: Record<string, Rate> };
  false_positives: { rate: number | null; flagged: string[]; n: number };
  latency_ms: { overhead: { p50: number | null; p95: number | null } };
}

export interface RunSummary {
  totals: { attacks: number; attack_probes: number; benign: number; errors: number };
  asr: {
    overall: ModeRates;
    base: ModeRates;
    mutated: ModeRates;
    by_category: Record<string, ModeRates>;
  };
  caught_by: Record<string, Record<string, number>>;
  false_positives: { rate: number | null; flagged: string[]; n: number; errors: number };
  latency_ms: {
    n: number;
    unprotected: { p50: number | null; p95: number | null };
    protected: { p50: number | null; p95: number | null };
    overhead: { p50: number | null; p95: number | null };
  };
  regression?: {
    previous_run_id: string | null;
    tolerance: number;
    deltas: Record<string, number>;
    regressed: string[];
  };
  layers?: Record<string, LayerSummary>;
}

export interface RunInfo {
  id: string;
  target: string;
  status: string;
  started_at: string;
  finished_at: string | null;
  seed: number;
  previous_run_id: string | null;
  asr_unprotected: number | null;
  asr_protected: number | null;
  false_positive_rate: number | null;
  regressed: string[];
}

export interface RunDetail extends RunInfo {
  error: string | null;
  config_snapshot: Record<string, unknown>;
  summary: RunSummary | null;
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string | null,
    message: string,
  ) {
    super(message);
  }
}

export interface Api {
  get<T>(path: string): Promise<T>;
  send<T>(method: "POST" | "PUT", path: string, body?: unknown): Promise<T>;
  download(path: string): Promise<Blob>;
}

async function failure(response: Response): Promise<ApiError> {
  let code: string | null = null;
  let message = `HTTP ${response.status}`;
  try {
    const body = (await response.json()) as { error?: { code?: string; message?: string } };
    code = body.error?.code ?? null;
    message = body.error?.message ?? message;
  } catch {
    // not JSON: keep the status line
  }
  return new ApiError(response.status, code, message);
}

export function createApi(
  baseUrl: string,
  key: string,
  onUnauthorized: () => void,
  fetcher: typeof fetch = (...args) => fetch(...args),
): Api {
  const root = baseUrl.replace(/\/+$/, "");
  async function call(method: string, path: string, body?: unknown): Promise<Response> {
    const headers: Record<string, string> = { Authorization: `Bearer ${key}` };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const response = await fetcher(root + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "omit",
      cache: "no-store",
    });
    if (response.status === 401) onUnauthorized();
    if (!response.ok) throw await failure(response);
    return response;
  }
  return {
    async get<T>(path: string) {
      return (await (await call("GET", path)).json()) as T;
    },
    async send<T>(method: "POST" | "PUT", path: string, body?: unknown) {
      return (await (await call(method, path, body)).json()) as T;
    },
    async download(path: string) {
      return (await call("GET", path)).blob();
    },
  };
}

export function query(params: Record<string, string | number | null | undefined>): string {
  const search = new URLSearchParams();
  for (const [name, value] of Object.entries(params)) {
    if (value !== null && value !== undefined && value !== "") search.set(name, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}
