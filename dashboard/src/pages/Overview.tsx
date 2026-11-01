import { useState } from "react";
import { ATTACK_CLASSES, query, type RangeName, type Stats } from "../api";
import { Bars, CLASS_SERIES } from "../components/Bars";
import { Guard } from "../components/States";
import { Card, RangePicker, StatTile, Table, cell } from "../components/Ui";
import { count, ms, pct, shortTime } from "../format";
import { useData } from "../useData";

export function Overview() {
  const [range, setRange] = useState<RangeName>("24h");
  const stats = useData<Stats>(`/admin/stats${query({ range })}`);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-xl font-semibold">Overview</h1>
        <RangePicker value={range} onChange={setRange} />
      </div>
      <Guard
        what="stats"
        state={stats}
        isEmpty={(s) => s.totals.events === 0}
        empty="No traffic in this range. Send requests through the gateway to see them here."
      >
        {(s) => <OverviewBody stats={s} />}
      </Guard>
    </div>
  );
}

function OverviewBody({ stats }: { stats: Stats }) {
  const { totals } = stats;
  const points = (kind: "blocked" | "redacted") =>
    stats.series.map((p) => ({ time: shortTime(p.ts, stats.bucket_seconds), ...p[kind] }));
  return (
    <>
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatTile label="Requests" value={count(totals.requests)} hint={`${count(totals.events)} items inspected`} />
        <StatTile label="Block rate" value={pct(totals.block_rate)} hint={`${count(totals.blocked)} blocked or quarantined`} />
        <StatTile label="Redacted" value={count(totals.redacted)} />
        <StatTile
          label="Gateway latency p95"
          value={ms(stats.latency_ms.p95)}
          hint={`p50 ${ms(stats.latency_ms.p50)} · judge calls ${count(totals.judge_calls)}`}
        />
      </div>
      <div className="grid gap-4 xl:grid-cols-2">
        <Card title="Blocked by attack class">
          <Bars data={points("blocked")} xKey="time" series={CLASS_SERIES} stacked label="Blocked events over time by attack class" />
        </Card>
        <Card title="Redacted by attack class">
          <Bars data={points("redacted")} xKey="time" series={CLASS_SERIES} stacked label="Redacted events over time by attack class" />
        </Card>
      </div>
      <Card title="By attack class">
        <Table head={["Attack class", "Blocked", "Redacted"]} caption="Blocked and redacted events by attack class">
          {ATTACK_CLASSES.map((c) => {
            const name = CLASS_SERIES.find((s) => s.key === c)?.name ?? c;
            return (
              <tr key={c}>
                <td className={cell}>{name}</td>
                <td className={`${cell} num`}>{count(stats.by_class[c].blocked)}</td>
                <td className={`${cell} num`}>{count(stats.by_class[c].redacted)}</td>
              </tr>
            );
          })}
        </Table>
      </Card>
    </>
  );
}
