import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../App";
import { createApi, query } from "../api";

const KEY = "aisg_admin_test_key_0123456789";
const XSS = `<img src=x onerror="window.pwned=1"><script>window.pwned=2</script>`;

type Handler = (url: URL, init: RequestInit) => Response | Promise<Response>;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

const STATS = {
  range: "24h",
  since: "2026-10-30T12:00:00+00:00",
  until: "2026-10-31T12:00:00+00:00",
  bucket_seconds: 3600,
  totals: { events: 4, requests: 3, blocked: 2, redacted: 1, allowed: 1, block_rate: 0.5, judge_calls: 1, by_direction: {}, by_action: {} },
  latency_ms: { p50: 1.5, p95: 9.25 },
  by_class: { A1: { blocked: 2, redacted: 0 }, A2: { blocked: 0, redacted: 0 }, A3: { blocked: 0, redacted: 1 }, A4: { blocked: 0, redacted: 0 } },
  series: [{ ts: "2026-10-31T11:00:00+00:00", blocked: { A1: 2, A2: 0, A3: 0, A4: 0 }, redacted: { A1: 0, A2: 0, A3: 1, A4: 0 } }],
};

const EVENT = {
  id: "e1",
  request_id: "r1",
  ts: "2026-10-31T11:30:00+00:00",
  app: "support-bot",
  session: null,
  direction: "request",
  role: "user",
  action: "block",
  risk_score: 0.9,
  latency_ms: 2,
  judge_used: false,
  upstream_model: null,
  ruleset_version: "abc",
  attack_classes: ["A1"],
  detectors: ["injection_rules"],
  excerpt_redacted: XSS,
};

const RUN_SUMMARY = {
  totals: { attacks: 2, attack_probes: 4, benign: 2, errors: 0 },
  asr: {
    overall: { unprotected: { rate: 1, successes: 4, n: 4, errors: 0 }, protected: { rate: 0.25, successes: 1, n: 4, errors: 0 }, block_rate: 0.75 },
    base: { unprotected: { rate: 1, successes: 2, n: 2, errors: 0 }, protected: { rate: 0, successes: 0, n: 2, errors: 0 }, block_rate: 1 },
    mutated: { unprotected: { rate: 1, successes: 2, n: 2, errors: 0 }, protected: { rate: 0.5, successes: 1, n: 2, errors: 0 }, block_rate: 0.5 },
    by_category: {
      direct_injection: { unprotected: { rate: 1, successes: 4, n: 4, errors: 0 }, protected: { rate: 0.25, successes: 1, n: 4, errors: 0 }, block_rate: 0.75 },
    },
  },
  caught_by: { layer: { "1": 2, "2": 1 }, detector: { injection_rules: 2 }, intervention: { blocked: 3 } },
  false_positives: { rate: 0, flagged: [], n: 2, errors: 0 },
  latency_ms: { n: 2, unprotected: { p50: 10, p95: 12 }, protected: { p50: 20, p95: 30 }, overhead: { p50: 10, p95: 18 } },
  regression: { previous_run_id: null, tolerance: 0.02, deltas: {}, regressed: [] },
  layers: {
    "1": {
      asr: { overall: { rate: 0.75, successes: 3, n: 4, errors: 0 }, by_category: { direct_injection: { rate: 0.75, successes: 3, n: 4, errors: 0 } } },
      false_positives: { rate: 0, flagged: [], n: 2 },
      latency_ms: { overhead: { p50: 2, p95: 4 } },
    },
  },
};

let routes: Record<string, Handler>;
let calls: { url: URL; init: RequestInit }[];

function route(path: string, body: unknown) {
  routes[path] = () => json(body);
}

function handle(path: string, handler: Handler) {
  routes[path] = handler;
}

beforeEach(() => {
  calls = [];
  routes = {};
  route("/admin/stats", STATS);
  route("/admin/events", { events: [EVENT], next_cursor: null });
  route("/admin/events/e1", { ...EVENT, findings: [{ detector: "injection_rules", attack_class: "A1", severity: "high", score: 0.9, rule_id: "inj-1", reason: `Matched ${XSS}`, span: [0, 5], layer: 1, message_index: null }] });
  route("/redteam/runs", []);
  vi.stubGlobal("fetch", async (input: string, init: RequestInit = {}) => {
    const url = new URL(input);
    calls.push({ url, init });
    const handler = routes[url.pathname];
    return handler ? handler(url, init) : json({ error: { message: "not found" } }, 404);
  });
  window.location.hash = "";
});

afterEach(() => {
  vi.unstubAllGlobals();
});

async function signIn(key = KEY) {
  const user = userEvent.setup();
  render(<App />);
  await user.type(screen.getByLabelText("Admin key"), key);
  await user.click(screen.getByRole("button", { name: "Sign in" }));
  return user;
}

describe("sign-in and the admin key", () => {
  it("sends the key as a bearer token and never stores it", async () => {
    await signIn();
    expect(await screen.findByText("Block rate")).toBeInTheDocument();
    expect(calls.every((c) => (c.init.headers as Record<string, string>).Authorization === `Bearer ${KEY}`)).toBe(true);
    expect(calls.every((c) => c.init.credentials === "omit")).toBe(true);
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
    expect(document.cookie).toBe("");
    expect(window.location.href).not.toContain(KEY);
  });

  it("rejects a key that is not an admin key", async () => {
    handle("/admin/stats", () => json({ error: { code: "wrong_key_role", message: "needs admin" } }, 403));
    await signIn("aisg_client_key");
    expect(await screen.findByRole("alert")).toHaveTextContent("not an admin key");
  });

  it("returns to sign-in when the key stops working", async () => {
    const user = await signIn();
    await screen.findByText("Block rate");
    handle("/admin/events", () => json({ error: { message: "revoked" } }, 401));
    await user.click(screen.getByRole("link", { name: "Events" }));
    expect(await screen.findByLabelText("Admin key")).toBeInTheDocument();
  });
});

describe("logged text is never rendered as HTML", () => {
  it("escapes excerpts and finding reasons", async () => {
    const user = await signIn();
    await user.click(screen.getByRole("link", { name: "Events" }));
    const excerpts = await screen.findAllByText(XSS);
    expect(excerpts.length).toBeGreaterThan(0);
    await user.click(screen.getByText("support-bot"));
    expect(await screen.findByText(`Matched ${XSS}`)).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
    expect(document.querySelector("main script")).toBeNull();
    expect((window as unknown as { pwned?: number }).pwned).toBeUndefined();
  });
});

describe("loading and empty states", () => {
  it("shows a loading state, then an empty one when there is no traffic", async () => {
    let release: (r: Response) => void = () => undefined;
    handle("/admin/stats", (url) =>
      url.searchParams.get("range") === "1h"
        ? json(STATS)
        : new Promise<Response>((resolve) => {
            release = resolve;
          }),
    );
    await signIn();
    expect(await screen.findByRole("status")).toHaveTextContent("Loading stats");
    release(json({ ...STATS, totals: { ...STATS.totals, events: 0 } }));
    expect(await screen.findByText(/No traffic in this range/)).toBeInTheDocument();
  });

  it("shows an empty run list", async () => {
    const user = await signIn();
    await user.click(screen.getByRole("link", { name: "Red-team runs" }));
    expect(await screen.findByText(/No runs yet/)).toBeInTheDocument();
  });

  it("shows an error state with a retry", async () => {
    const user = await signIn();
    handle("/admin/documents", () => json({ error: { message: "database down" } }, 500));
    route("/admin/quarantine", []);
    await user.click(screen.getByRole("link", { name: "Documents" }));
    expect(await screen.findByText("database down")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
    expect(await screen.findByText("Nothing waiting for review.")).toBeInTheDocument();
  });
});

describe("red-team run page", () => {
  it("leads with attack success without versus with the gateway, per category and layer", async () => {
    route("/redteam/runs", [{ id: "run1", target: "demo_rag", status: "completed", started_at: "2026-10-31T10:00:00+00:00", finished_at: null, seed: 1, previous_run_id: null, asr_unprotected: 1, asr_protected: 0.25, false_positive_rate: 0, regressed: [] }]);
    route("/redteam/runs/run1", { id: "run1", target: "demo_rag", status: "completed", started_at: "2026-10-31T10:00:00+00:00", finished_at: null, seed: 1, previous_run_id: null, asr_unprotected: 1, asr_protected: 0.25, false_positive_rate: 0, regressed: [], error: null, config_snapshot: { model: "sim-obedient", model_simulated: true }, summary: RUN_SUMMARY });
    const user = await signIn();
    await user.click(screen.getByRole("link", { name: "Red-team runs" }));
    await user.click(await screen.findByRole("link", { name: /2026|10/ }));
    expect(await screen.findByText("Attack success without gateway")).toBeInTheDocument();
    const table = screen.getByRole("table", { name: "Attack success rate per category" });
    const headers = within(table).getAllByRole("columnheader").map((h) => h.textContent);
    expect(headers).toEqual(["Category", "Without gateway", "Rules only", "With gateway", "Probes"]);
    const row = within(table).getByText("direct injection").closest("tr");
    expect(row).not.toBeNull();
    expect(within(row as HTMLElement).getAllByRole("cell").map((c) => c.textContent)).toEqual(["direct injection", "100.0%", "75.0%", "25.0%", "4"]);
    expect(screen.getByText("(simulated)", { exact: false })).toBeInTheDocument();
  });
});

describe("policies", () => {
  it("shows a validation error from the gateway", async () => {
    const policy = { id: 1, created_at: "2026-10-31T10:00:00+00:00", created_by: "policies.yaml", comment: null, active: true, content: "thresholds: {}", ruleset_version: "v1", config: { thresholds: { allow_below: 0.3, judge_band: [0.3, 0.7], block_at: 0.7 }, actions: { A1: { user: "block" } }, weights: {}, judge: { enabled: true, timeout_ms: 4000, max_calls_per_minute: 30 } } };
    handle("/admin/policies", (_url, init) =>
      init.method === "PUT" ? json({ error: { code: "invalid_policy", message: "Invalid policy: block_at must be a number" } }, 422) : json(policy),
    );
    route("/admin/policies/versions", [policy]);
    const user = await signIn();
    await user.click(screen.getByRole("link", { name: "Policies" }));
    const editor = await screen.findByLabelText("Policy YAML");
    await user.clear(editor);
    await user.type(editor, "block_at: soon");
    await user.click(screen.getByRole("button", { name: "Validate and save" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("block_at must be a number");
  });
});

describe("api helpers", () => {
  it("builds query strings without empty values", () => {
    expect(query({ range: "1h", app: "", action: null, limit: 5 })).toBe("?range=1h&limit=5");
    expect(query({})).toBe("");
  });

  it("reports 401 and raises gateway errors", async () => {
    const unauthorized = vi.fn();
    const api = createApi("http://gw.test/", "k", unauthorized, async () => json({ error: { code: "x", message: "nope" } }, 401));
    await expect(api.get("/admin/stats")).rejects.toMatchObject({ status: 401, code: "x", message: "nope" });
    expect(unauthorized).toHaveBeenCalledOnce();
  });
});
