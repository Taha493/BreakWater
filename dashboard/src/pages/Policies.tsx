import { useState } from "react";
import { type ActivePolicy, type PolicyVersion, type PolicyVersionInfo } from "../api";
import { useApi } from "../context";
import { Guard } from "../components/States";
import { Card, Table, cell } from "../components/Ui";
import { when } from "../format";
import { useData } from "../useData";

export function Policies() {
  const active = useData<ActivePolicy>("/admin/policies");
  const versions = useData<PolicyVersionInfo[]>("/admin/policies/versions");
  const reload = () => {
    active.reload();
    versions.reload();
  };
  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Policies</h1>
      <Guard what="policy" state={active}>
        {(policy) => (
          <div className="grid gap-4 xl:grid-cols-2">
            <Summary policy={policy} />
            <Editor key={policy.id} policy={policy} onSaved={reload} />
          </div>
        )}
      </Guard>
      <Card title="Version history">
        <Guard what="versions" state={versions} isEmpty={(v) => v.length === 0}>
          {(rows) => <History rows={rows} onChange={reload} />}
        </Guard>
      </Card>
    </div>
  );
}

function Summary({ policy }: { policy: ActivePolicy }) {
  const { thresholds, actions, judge } = policy.config;
  return (
    <Card title={`Active: version ${policy.id}`}>
      <p className="mb-3 text-xs text-muted">
        Set by {policy.created_by} on {when(policy.created_at)} · ruleset {policy.ruleset_version}
      </p>
      <dl className="mb-4 grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
        <dt className="text-muted">Allow below</dt>
        <dd className="num">{thresholds.allow_below}</dd>
        <dt className="text-muted">Judge band</dt>
        <dd className="num">
          {thresholds.judge_band[0]} to {thresholds.judge_band[1]}
          {judge.enabled ? "" : " (judge off in this policy)"}
        </dd>
        <dt className="text-muted">Block at</dt>
        <dd className="num">{thresholds.block_at}</dd>
      </dl>
      <Table head={["Class", "Role", "Action"]} caption="Actions by attack class and role">
        {Object.entries(actions).flatMap(([attackClass, roles]) =>
          Object.entries(roles).map(([role, action]) => (
            <tr key={`${attackClass}-${role}`}>
              <td className={cell}>{attackClass}</td>
              <td className={cell}>{role}</td>
              <td className={cell}>{action.replace(/_/g, " ")}</td>
            </tr>
          )),
        )}
      </Table>
    </Card>
  );
}

function Editor({ policy, onSaved }: { policy: ActivePolicy; onSaved: () => void }) {
  const api = useApi();
  const [content, setContent] = useState(policy.content);
  const [comment, setComment] = useState("");
  const [status, setStatus] = useState<{ kind: "error" | "saved"; text: string } | null>(null);
  const [saving, setSaving] = useState(false);

  async function save() {
    setSaving(true);
    setStatus(null);
    try {
      const saved = await api.send<ActivePolicy>("PUT", "/admin/policies", {
        content,
        comment: comment || undefined,
      });
      setStatus({ kind: "saved", text: `Saved as version ${saved.id}; it applies now.` });
      setComment("");
      onSaved();
    } catch (e) {
      setStatus({ kind: "error", text: e instanceof Error ? e.message : "Save failed" });
    } finally {
      setSaving(false);
    }
  }

  return (
    <Card title="Edit (YAML)">
      <textarea
        aria-label="Policy YAML"
        value={content}
        onChange={(e) => setContent(e.target.value)}
        spellCheck={false}
        className="h-80 w-full rounded-md border border-line bg-surface-2 p-2 font-mono text-xs"
      />
      <div className="mt-2 flex flex-wrap items-center gap-2">
        <input
          aria-label="Change note"
          placeholder="What changed and why"
          value={comment}
          maxLength={256}
          onChange={(e) => setComment(e.target.value)}
          className="min-w-0 flex-1 rounded-md border border-line bg-surface px-2 py-1 text-sm"
        />
        <button
          onClick={() => void save()}
          disabled={saving || content === policy.content}
          className="rounded-md bg-accent px-3 py-1 text-sm font-semibold text-white disabled:opacity-50"
        >
          Validate and save
        </button>
      </div>
      {status && (
        <p role={status.kind === "error" ? "alert" : "status"} className={`mt-2 text-sm ${status.kind === "error" ? "text-critical" : "text-good"}`}>
          {status.text}
        </p>
      )}
    </Card>
  );
}

function History({ rows, onChange }: { rows: PolicyVersionInfo[]; onChange: () => void }) {
  const api = useApi();
  const [viewing, setViewing] = useState<PolicyVersion | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function activate(id: number) {
    setError(null);
    try {
      await api.send("POST", `/admin/policies/versions/${id}/activate`);
      onChange();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Rollback failed");
    }
  }

  return (
    <>
      {error && (
        <p role="alert" className="mb-2 text-sm text-critical">
          {error}
        </p>
      )}
      <Table head={["Version", "Saved", "By", "Note", ""]} caption="Policy versions">
        {rows.map((v) => (
          <tr key={v.id}>
            <td className={`${cell} num`}>
              {v.id}
              {v.active && <span className="ml-2 text-xs font-semibold text-good">✓ active</span>}
            </td>
            <td className={`${cell} whitespace-nowrap`}>{when(v.created_at)}</td>
            <td className={`${cell} break-all`}>{v.created_by}</td>
            <td className={cell}>{v.comment ?? "—"}</td>
            <td className={`${cell} whitespace-nowrap`}>
              <button
                onClick={() => void api.get<PolicyVersion>(`/admin/policies/versions/${v.id}`).then(setViewing, () => setError("Could not load that version"))}
                className="mr-2 underline"
              >
                View
              </button>
              {!v.active && (
                <button onClick={() => void activate(v.id)} className="underline">
                  Roll back to this
                </button>
              )}
            </td>
          </tr>
        ))}
      </Table>
      {viewing && (
        <div className="mt-3">
          <div className="mb-1 text-xs text-muted">Version {viewing.id}</div>
          <pre className="max-h-80 overflow-auto rounded-md bg-surface-2 p-2 text-xs">{viewing.content}</pre>
        </div>
      )}
    </>
  );
}
