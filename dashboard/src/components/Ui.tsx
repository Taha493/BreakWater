import type { ReactNode } from "react";
import { RANGES, type RangeName } from "../api";

export function Card({ title, children, actions }: { title?: string; children: ReactNode; actions?: ReactNode }) {
  return (
    // min-w-0: inside a grid cell, charts must be able to shrink to the cell's width.
    <section className="min-w-0 rounded-lg border border-line bg-surface p-4">
      {(title || actions) && (
        <div className="mb-3 flex items-center justify-between gap-2">
          {title && <h2 className="text-sm font-semibold">{title}</h2>}
          {actions}
        </div>
      )}
      {children}
    </section>
  );
}

export function StatTile({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="rounded-lg border border-line bg-surface p-4">
      <div className="text-sm text-ink-2">{label}</div>
      <div className="mt-1 text-2xl font-semibold">{value}</div>
      {hint && <div className="mt-1 text-xs text-muted">{hint}</div>}
    </div>
  );
}

export function RangePicker({ value, onChange }: { value: RangeName; onChange: (r: RangeName) => void }) {
  const names: Record<RangeName, string> = { "1h": "Last hour", "24h": "24 hours", "7d": "7 days", "30d": "30 days" };
  return (
    <div role="group" aria-label="Time range" className="inline-flex rounded-md border border-line bg-surface p-0.5">
      {RANGES.map((r) => (
        <button
          key={r}
          aria-pressed={r === value}
          onClick={() => onChange(r)}
          className={`rounded px-3 py-1 text-sm ${r === value ? "bg-surface-2 font-semibold" : "text-ink-2 hover:bg-surface-2"}`}
        >
          {names[r]}
        </button>
      ))}
    </div>
  );
}

const ACTION_STYLE: Record<string, string> = {
  block: "text-critical",
  quarantine: "text-critical",
  redact: "text-warning",
  require_confirmation: "text-warning",
  allow: "text-good",
};

/** An action as text plus a symbol, so it never relies on color alone. */
export function ActionBadge({ action }: { action: string }) {
  const symbol = action === "allow" ? "✓" : action === "redact" ? "◐" : "✕";
  return (
    <span className={`whitespace-nowrap font-medium ${ACTION_STYLE[action] ?? "text-ink-2"}`}>
      <span aria-hidden="true">{symbol} </span>
      {action.replace(/_/g, " ")}
    </span>
  );
}

export function Table({ head, children, caption }: { head: string[]; children: ReactNode; caption?: string }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-left text-sm">
        {caption && <caption className="sr-only">{caption}</caption>}
        <thead>
          <tr className="border-b border-line text-xs text-muted">
            {head.map((h) => (
              <th key={h} scope="col" className="px-2 py-2 font-medium">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

export const cell = "border-b border-line px-2 py-2 align-top";
