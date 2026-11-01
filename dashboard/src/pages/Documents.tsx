import { useState } from "react";
import { type DocumentRow, type Documents as DocumentsData, type QuarantineEntry } from "../api";
import { useApi } from "../context";
import { Guard } from "../components/States";
import { Card, StatTile, Table, cell } from "../components/Ui";
import { count, label, when } from "../format";
import { useData } from "../useData";

const STATUSES = ["clean", "suspicious", "quarantined"];

export function Documents() {
  const docs = useData<DocumentsData>("/admin/documents?limit=10");
  const queue = useData<QuarantineEntry[]>("/admin/quarantine?status=pending");
  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Documents and quarantine</h1>
      <Guard what="documents" state={docs}>
        {(d) => (
          <>
            <div className="grid grid-cols-3 gap-3">
              {STATUSES.map((s) => (
                <StatTile key={s} label={`${label(s)} documents`} value={count(d.counts[s] ?? 0)} />
              ))}
            </div>
            <Card title="Riskiest documents">
              <DocumentTable rows={d.top_risky} empty="No document has scored any risk yet." />
            </Card>
          </>
        )}
      </Guard>
      <Card title="Review queue">
        <Guard
          what="quarantine queue"
          state={queue}
          isEmpty={(q) => q.length === 0}
          empty="Nothing waiting for review."
        >
          {(items) => <Queue items={items} onChange={() => { queue.reload(); docs.reload(); }} />}
        </Guard>
      </Card>
    </div>
  );
}

function DocumentTable({ rows, empty }: { rows: DocumentRow[]; empty: string }) {
  if (rows.length === 0) return <p className="text-sm text-muted">{empty}</p>;
  return (
    <Table head={["Document", "Source", "Trust", "Status", "Risk", "Quarantined chunks", "Scanned"]} caption="Documents">
      {rows.map((d) => (
        <tr key={d.id}>
          <td className={`${cell} break-all`}>{d.doc_id}</td>
          <td className={cell}>{d.source ?? "—"}</td>
          <td className={cell}>{label(d.trust_level)}</td>
          <td className={cell}>{d.status}</td>
          <td className={`${cell} num`}>{d.risk_score.toFixed(2)}</td>
          <td className={`${cell} num`}>
            {d.quarantined_chunks} of {d.chunks}
          </td>
          <td className={`${cell} whitespace-nowrap`}>{when(d.created_at)}</td>
        </tr>
      ))}
    </Table>
  );
}

function Queue({ items, onChange }: { items: QuarantineEntry[]; onChange: () => void }) {
  const api = useApi();
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function review(id: string, decision: "release" | "keep") {
    setBusy(id);
    setError(null);
    try {
      await api.send("POST", `/admin/quarantine/${encodeURIComponent(id)}/${decision}`);
      onChange();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Request failed");
    } finally {
      setBusy(null);
    }
  }

  return (
    <>
      {error && (
        <p role="alert" className="mb-2 text-sm text-critical">
          {error}
        </p>
      )}
      <Table head={["Document", "Hidden as", "Risk", "Reason", "Excerpt", ""]} caption="Quarantined chunks">
        {items.map((q) => (
          <tr key={q.id}>
            <td className={`${cell} break-all`}>
              {q.doc_id} <span className="text-muted">#{q.chunk_index}</span>
            </td>
            <td className={cell}>{q.hidden_kind ? label(q.hidden_kind) : "visible text"}</td>
            <td className={`${cell} num`}>{q.risk_score.toFixed(2)}</td>
            <td className={cell}>{q.reason}</td>
            <td className={`${cell} max-w-xs text-ink-2`}>
              <span className="line-clamp-3 break-words">{q.excerpt_redacted}</span>
            </td>
            <td className={`${cell} whitespace-nowrap`}>
              <button
                disabled={busy === q.id}
                onClick={() => void review(q.id, "release")}
                className="mr-2 rounded-md border border-line px-2 py-1"
              >
                Release
              </button>
              <button
                disabled={busy === q.id}
                onClick={() => void review(q.id, "keep")}
                className="rounded-md border border-line px-2 py-1"
              >
                Keep quarantined
              </button>
            </td>
          </tr>
        ))}
      </Table>
    </>
  );
}
