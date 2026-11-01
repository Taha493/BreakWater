import { useState } from "react";
import { ATTACK_CLASSES, query, type EventDetail, type EventPage, type RangeName } from "../api";
import { useApi } from "../context";
import { Empty, ErrorState, Guard, Loading } from "../components/States";
import { ActionBadge, Card, RangePicker, Table, cell } from "../components/Ui";
import { label, when } from "../format";
import { useData } from "../useData";

const ACTIONS = ["block", "quarantine", "redact", "require_confirmation", "allow"];

export function Events() {
  const api = useApi();
  const [range, setRange] = useState<RangeName>("24h");
  const [filters, setFilters] = useState({ app: "", action: "", attack_class: "", detector: "" });
  const [selected, setSelected] = useState<string | null>(null);
  const path = `/admin/events${query({ range, limit: 50, ...filters })}`;
  const first = useData<EventPage>(path);
  // Pages loaded with "Load more", kept only while they belong to the current filters.
  const [extra, setExtra] = useState<{ path: string; pages: EventPage[] }>({ path, pages: [] });
  const morePages = extra.path === path ? extra.pages : [];
  const error = first.error;
  const rows = first.data ? [first.data, ...morePages].flatMap((p) => p.events) : null;
  const cursor = (morePages.at(-1) ?? first.data)?.next_cursor ?? null;

  async function more() {
    if (!cursor) return;
    const page = await api.get<EventPage>(`${path}&cursor=${encodeURIComponent(cursor)}`);
    setExtra({ path, pages: [...morePages, page] });
  }

  const set = (name: keyof typeof filters) => (e: { target: { value: string } }) =>
    setFilters((f) => ({ ...f, [name]: e.target.value }));
  const field = "rounded-md border border-line bg-surface px-2 py-1 text-sm";

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-xl font-semibold">Events</h1>
        <RangePicker value={range} onChange={setRange} />
      </div>
      <div className="flex flex-wrap gap-2" aria-label="Filters">
        <input aria-label="App" placeholder="App" value={filters.app} onChange={set("app")} className={field} />
        <select aria-label="Action" value={filters.action} onChange={set("action")} className={field}>
          <option value="">Any action</option>
          {ACTIONS.map((a) => (
            <option key={a} value={a}>
              {label(a)}
            </option>
          ))}
        </select>
        <select aria-label="Attack class" value={filters.attack_class} onChange={set("attack_class")} className={field}>
          <option value="">Any class</option>
          {ATTACK_CLASSES.map((c) => (
            <option key={c}>{c}</option>
          ))}
        </select>
        <input aria-label="Detector" placeholder="Detector" value={filters.detector} onChange={set("detector")} className={field} />
      </div>
      <div className="grid gap-4 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <Card>
          {error ? (
            <ErrorState message={error} />
          ) : rows === null ? (
            <Loading what="events" />
          ) : rows.length === 0 ? (
            <Empty>No events match these filters.</Empty>
          ) : (
            <>
              <Table head={["Time", "App", "Kind", "Action", "Risk", "Classes", "Detectors", "Excerpt"]} caption="Events">
                {rows.map((e) => (
                  <tr
                    key={e.id}
                    onClick={() => setSelected(e.id)}
                    className={`cursor-pointer hover:bg-surface-2 ${selected === e.id ? "bg-surface-2" : ""}`}
                  >
                    <td className={`${cell} whitespace-nowrap`}>{when(e.ts)}</td>
                    <td className={cell}>{e.app ?? "—"}</td>
                    <td className={cell}>{label(e.direction)}</td>
                    <td className={cell}>
                      <ActionBadge action={e.action} />
                    </td>
                    <td className={`${cell} num`}>{e.risk_score.toFixed(2)}</td>
                    <td className={cell}>{e.attack_classes.join(", ") || "—"}</td>
                    <td className={cell}>{e.detectors.join(", ") || "—"}</td>
                    <td className={`${cell} max-w-xs truncate text-ink-2`} title={e.excerpt_redacted}>
                      {e.excerpt_redacted}
                    </td>
                  </tr>
                ))}
              </Table>
              {cursor && (
                <button onClick={() => void more()} className="mt-3 text-sm underline">
                  Load more
                </button>
              )}
            </>
          )}
        </Card>
        <Card title="Event detail">
          {selected ? <Detail id={selected} /> : <Empty>Select an event to see its findings.</Empty>}
        </Card>
      </div>
    </div>
  );
}

function Detail({ id }: { id: string }) {
  const detail = useData<EventDetail>(`/admin/events/${encodeURIComponent(id)}`);
  return (
    <Guard what="event" state={detail}>
      {(e) => (
        <div className="space-y-3 text-sm">
          <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1">
            <dt className="text-muted">Request</dt>
            <dd className="break-all">{e.request_id}</dd>
            <dt className="text-muted">Action</dt>
            <dd>
              <ActionBadge action={e.action} /> · risk {e.risk_score.toFixed(2)}
              {e.judge_used ? " · judge asked" : ""}
            </dd>
            <dt className="text-muted">Role</dt>
            <dd>{e.role}</dd>
            <dt className="text-muted">Latency</dt>
            <dd>{e.latency_ms.toFixed(1)} ms</dd>
            <dt className="text-muted">Ruleset</dt>
            <dd>{e.ruleset_version}</dd>
          </dl>
          <div>
            <div className="mb-1 text-xs text-muted">Excerpt (secrets and personal data redacted)</div>
            <pre className="whitespace-pre-wrap break-words rounded-md bg-surface-2 p-2 text-xs">{e.excerpt_redacted}</pre>
          </div>
          {e.findings.length === 0 ? (
            <Empty>No findings.</Empty>
          ) : (
            <Table head={["Layer", "Detector", "Rule", "Class", "Score", "Reason"]} caption="Findings">
              {e.findings.map((f, i) => (
                <tr key={i}>
                  <td className={`${cell} num`}>{f.layer}</td>
                  <td className={cell}>{f.detector}</td>
                  <td className={`${cell} break-words`}>{f.rule_id ?? "—"}</td>
                  <td className={cell}>{f.attack_class}</td>
                  <td className={`${cell} num`}>{f.score.toFixed(2)}</td>
                  <td className={cell}>{f.reason}</td>
                </tr>
              ))}
            </Table>
          )}
        </div>
      )}
    </Guard>
  );
}
