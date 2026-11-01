export function pct(value: number | null | undefined, digits = 1): string {
  return value === null || value === undefined ? "n/a" : `${(value * 100).toFixed(digits)}%`;
}

export function ms(value: number | null | undefined): string {
  return value === null || value === undefined ? "n/a" : `${value.toFixed(1)} ms`;
}

export function count(value: number): string {
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1)}M`;
  if (value >= 10_000) return `${(value / 1000).toFixed(1)}K`;
  return value.toLocaleString("en-US");
}

export function when(iso: string | null | undefined): string {
  if (!iso) return "n/a";
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString();
}

export function shortTime(iso: string, bucketSeconds: number): string {
  const date = new Date(iso);
  return bucketSeconds >= 86_400
    ? date.toLocaleDateString(undefined, { month: "short", day: "numeric" })
    : date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

export function label(name: string): string {
  return name.replace(/_/g, " ");
}
