import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  type TooltipContentProps,
} from "recharts";

export interface Series {
  key: string;
  name: string;
  color: string; // a CSS color, usually var(--series-n)
}

// Fixed slots: attack classes and run modes keep their color whatever is filtered.
export const CLASS_SERIES: Series[] = [
  { key: "A1", name: "A1 direct injection", color: "var(--series-1)" },
  { key: "A2", name: "A2 indirect injection", color: "var(--series-2)" },
  { key: "A3", name: "A3 data leakage", color: "var(--series-3)" },
  { key: "A4", name: "A4 tool abuse", color: "var(--series-4)" },
];

type Row = Record<string, string | number | null>;

function TooltipBox({
  active,
  payload,
  label,
  format,
}: TooltipContentProps<number, string> & { format: (v: number) => string }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-md border border-line bg-surface px-3 py-2 text-xs shadow-sm">
      <div className="mb-1 font-semibold">{String(label)}</div>
      {payload.map((item) => (
        <div key={String(item.dataKey)} className="flex items-center gap-2">
          <span aria-hidden="true" className="inline-block h-2 w-2 rounded-sm" style={{ background: item.color }} />
          <span className="text-ink-2">{item.name}</span>
          <span className="num ml-auto pl-3 font-medium">
            {typeof item.value === "number" ? format(item.value) : "n/a"}
          </span>
        </div>
      ))}
    </div>
  );
}

/** Columns per x value: stacked (parts of a whole) or grouped (side by side). */
export function Bars({
  data,
  xKey,
  series,
  stacked = false,
  height = 260,
  yFormat = (v) => String(v),
  yDomain,
  label,
}: {
  data: Row[];
  xKey: string;
  series: Series[];
  stacked?: boolean;
  height?: number;
  yFormat?: (v: number) => string;
  yDomain?: [number, number];
  label: string;
}) {
  return (
    <figure aria-label={label} className="m-0">
      <ResponsiveContainer width="100%" height={height}>
        <BarChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: 0 }} barGap={2} barCategoryGap="20%">
          <CartesianGrid vertical={false} stroke="var(--grid)" />
          <XAxis
            dataKey={xKey}
            tickLine={false}
            axisLine={{ stroke: "var(--axis)" }}
            tick={{ fill: "var(--muted)", fontSize: 12 }}
            minTickGap={12}
          />
          <YAxis
            tickLine={false}
            axisLine={false}
            tick={{ fill: "var(--muted)", fontSize: 12 }}
            tickFormatter={yFormat}
            domain={yDomain}
            allowDecimals={false}
            width={48}
          />
          <Tooltip
            cursor={{ fill: "var(--surface-2)" }}
            content={(props) => <TooltipBox {...(props as TooltipContentProps<number, string>)} format={yFormat} />}
          />
          <Legend
            iconType="square"
            iconSize={10}
            // Keep the series order, and label text in ink: the swatch carries the color.
            itemSorter={null}
            formatter={(value) => <span style={{ color: "var(--ink-2)" }}>{value}</span>}
            wrapperStyle={{ fontSize: 12 }}
          />
          {series.map((s, index) => (
            <Bar
              key={s.key}
              dataKey={s.key}
              name={s.name}
              fill={s.color}
              stackId={stacked ? "stack" : undefined}
              maxBarSize={24}
              // Rounded data end, square at the baseline; in a stack only the top segment.
              radius={!stacked || index === series.length - 1 ? [4, 4, 0, 0] : 0}
              // A 2px gap in the surface color between touching marks.
              stroke="var(--surface)"
              strokeWidth={1}
              isAnimationActive={false}
            />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </figure>
  );
}
