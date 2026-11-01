import { useState } from "react";
import { type RunDetail, type RunInfo, type RunSummary } from "../api";
import { useApi } from "../context";
import { Bars, type Series } from "../components/Bars";
import { Empty, Guard } from "../components/States";
import { Card, StatTile, Table, cell } from "../components/Ui";
import { label, ms, pct, when } from "../format";
import { useData } from "../useData";

// Fixed colors per mode, in an order that passes the adjacent-bar color checks in both
// themes (with or without the layer columns).
const WITHOUT: Series = { key: "without", name: "Without gateway", color: "var(--series-2)" };
const FULL: Series = { key: "full", name: "With gateway", color: "var(--series-1)" };
const LAYER_SERIES: Record<string, Series> = {
  "1": { key: "l1", name: "Rules only", color: "var(--series-3)" },
  "2": { key: "l2", name: "Rules + classifier", color: "var(--series-4)" },
};

export function RedTeam({ runId, open }: { runId: string | null; open: (id: string | null) => void }) {
  return runId ? <Run id={runId} back={() => open(null)} /> : <RunList open={open} />;
}

function RunList({ open }: { open: (id: string) => void }) {
  const runs = useData<RunInfo[]>("/redteam/runs?limit=100");
  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Red-team runs</h1>
      <Card>
        <Guard
          what="runs"
          state={runs}
          isEmpty={(r) => r.length === 0}
          empty="No runs yet. Start one with `breakwater redteam run --target demo_rag` or POST /redteam/runs."
        >
          {(rows) => (
            <Table head={["Started", "Target", "Status", "ASR without", "ASR with", "False positives", "Regression"]} caption="Red-team runs">
              {rows.map((r) => (
                <tr key={r.id} onClick={() => open(r.id)} className="cursor-pointer hover:bg-surface-2">
                  <td className={`${cell} whitespace-nowrap`}>
                    <a
                      href={`#/redteam/${r.id}`}
                      onClick={(e) => {
                        e.preventDefault();
                        open(r.id);
                      }}
                      className="underline"
                    >
                      {when(r.started_at)}
                    </a>
                  </td>
                  <td className={cell}>{r.target}</td>
                  <td className={cell}>{r.status}</td>
                  <td className={`${cell} num`}>{pct(r.asr_unprotected)}</td>
                  <td className={`${cell} num`}>{pct(r.asr_protected)}</td>
                  <td className={`${cell} num`}>{pct(r.false_positive_rate)}</td>
                  <td className={cell}>
                    {r.regressed.length ? (
                      <span className="font-medium text-critical">✕ {r.regressed.map(label).join(", ")}</span>
                    ) : (
                      "—"
                    )}
                  </td>
                </tr>
              ))}
            </Table>
          )}
        </Guard>
      </Card>
    </div>
  );
}

function Run({ id, back }: { id: string; back: () => void }) {
  const run = useData<RunDetail>(`/redteam/runs/${encodeURIComponent(id)}`);
  return (
    <div className="space-y-4">
      <button onClick={back} className="text-sm underline">
        ← All runs
      </button>
      <Guard what="run" state={run}>
        {(r) => <RunBody run={r} />}
      </Guard>
    </div>
  );
}

function rows(summary: RunSummary) {
  const layers = summary.layers ?? {};
  const categories = Object.entries(summary.asr.by_category);
  return [...categories, ["all categories", summary.asr.overall] as const].map(([name, modes]) => {
    const row: Record<string, string | number | null> = {
      category: label(name),
      without: modes.unprotected.rate,
      full: modes.protected.rate,
      n: modes.protected.n,
    };
    for (const [layer, data] of Object.entries(layers)) {
      const series = LAYER_SERIES[layer];
      if (!series) continue;
      row[series.key] = name === "all categories" ? data.asr.overall.rate : (data.asr.by_category[name]?.rate ?? null);
    }
    return row;
  });
}

function RunBody({ run }: { run: RunDetail }) {
  const api = useApi();
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const summary = run.summary;
  const config = run.config_snapshot;

  async function download(format: "html" | "md" | "json") {
    setDownloadError(null);
    try {
      const blob = await api.download(`/redteam/runs/${encodeURIComponent(run.id)}/report?format=${format}`);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `redteam-${run.id}.${format}`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setDownloadError(e instanceof Error ? e.message : "Download failed");
    }
  }

  const header = (
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div>
        <h1 className="text-xl font-semibold">Run against {run.target}</h1>
        <p className="text-sm text-muted">
          {run.status} · started {when(run.started_at)} · seed {run.seed} · model {String(config.model ?? "n/a")}
          {config.model_simulated ? " (simulated)" : ""}
        </p>
      </div>
      <div className="flex gap-2 text-sm">
        {(["html", "md", "json"] as const).map((f) => (
          <button key={f} onClick={() => void download(f)} className="rounded-md border border-line px-2 py-1">
            Download {f.toUpperCase()}
          </button>
        ))}
      </div>
    </div>
  );

  if (!summary) {
    return (
      <>
        {header}
        <Empty>{run.error ? `Run failed: ${run.error}` : "This run has no results yet."}</Empty>
      </>
    );
  }

  const layerSeries = Object.keys(summary.layers ?? {})
    .map((l) => LAYER_SERIES[l])
    .filter((s): s is Series => s !== undefined);
  const series = [WITHOUT, ...layerSeries, FULL];
  const data = rows(summary);
  const overall = summary.asr.overall;
  const regression = summary.regression;

  return (
    <>
      {header}
      {downloadError && (
        <p role="alert" className="text-sm text-critical">
          {downloadError}
        </p>
      )}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatTile label="Attack success without gateway" value={pct(overall.unprotected.rate)} hint={`${overall.unprotected.n} attack probes`} />
        <StatTile label="Attack success with gateway" value={pct(overall.protected.rate)} hint={`block rate ${pct(overall.block_rate)}`} />
        <StatTile
          label="False positive rate"
          value={pct(summary.false_positives.rate)}
          hint={`${summary.false_positives.flagged.length} of ${summary.false_positives.n} benign cases flagged`}
        />
        <StatTile
          label="Latency overhead p95"
          value={ms(summary.latency_ms.overhead.p95)}
          hint={`p50 ${ms(summary.latency_ms.overhead.p50)}`}
        />
      </div>
      <Card title="Attack success rate per category">
        <Bars data={data} xKey="category" series={series} yFormat={(v) => pct(v, 0)} yDomain={[0, 1]} label="Attack success rate per category, without and with the gateway" />
        <Table head={["Category", ...series.map((s) => s.name), "Probes"]} caption="Attack success rate per category">
          {data.map((row) => (
            <tr key={String(row.category)}>
              <td className={cell}>{row.category}</td>
              {series.map((s) => (
                <td key={s.key} className={`${cell} num`}>
                  {pct(row[s.key] as number | null)}
                </td>
              ))}
              <td className={`${cell} num`}>{row.n}</td>
            </tr>
          ))}
        </Table>
      </Card>
      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="Regression versus the previous comparable run">
          {regression?.previous_run_id ? (
            <Table head={["Category", "Change in ASR with gateway", ""]} caption="Regression">
              {Object.entries(regression.deltas).map(([name, delta]) => {
                const regressed = regression.regressed.includes(name);
                return (
                  <tr key={name}>
                    <td className={cell}>{label(name)}</td>
                    <td className={`${cell} num`}>{`${delta > 0 ? "+" : ""}${(delta * 100).toFixed(1)} pts`}</td>
                    <td className={cell}>
                      {regressed ? (
                        <span className="font-medium text-critical">✕ regressed</span>
                      ) : (
                        <span className="text-good">✓ ok</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </Table>
          ) : (
            <p className="text-sm text-muted">No previous comparable run (same target, attack set, seed, and mutations).</p>
          )}
        </Card>
        <Card title="What caught the attacks">
          <dl className="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-2 text-sm">
            {Object.entries(summary.caught_by).map(([kind, counts]) => (
              <div key={kind} className="contents">
                <dt className="text-muted">{label(kind)}</dt>
                <dd>
                  {Object.entries(counts)
                    .map(([name, n]) => `${label(name)}: ${n}`)
                    .join(", ") || "none"}
                </dd>
              </div>
            ))}
          </dl>
          {summary.false_positives.flagged.length > 0 && (
            <p className="mt-3 text-sm">
              <span className="text-muted">Benign cases flagged:</span> {summary.false_positives.flagged.join(", ")}
            </p>
          )}
        </Card>
      </div>
    </>
  );
}
