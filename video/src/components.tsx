import React from "react";
import { AbsoluteFill, Easing, interpolate, spring, useCurrentFrame, useVideoConfig } from "remotion";
import { C, MONO, SANS, STAGE_HEIGHT, WIDTH } from "./theme";

export const clamp = { extrapolateLeft: "clamp", extrapolateRight: "clamp" } as const;
export const easeOut = Easing.bezier(0.16, 1, 0.3, 1);

/** 0 to 1 on a soft spring, starting at `delay`. */
export const useEnter = (delay = 0, damping = 18) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  return spring({ frame: frame - delay, fps, config: { damping, mass: 0.8 } });
};

/** 1 until `from`, then fades to 0 over `length` frames. */
export const useLeave = (from: number, length = 16) =>
  interpolate(useCurrentFrame(), [from, from + length], [1, 0], { ...clamp, easing: easeOut });

export const FadeUp: React.FC<{
  delay?: number;
  distance?: number;
  style?: React.CSSProperties;
  children: React.ReactNode;
}> = ({ delay = 0, distance = 36, style, children }) => {
  const p = useEnter(delay);
  return (
    <div style={{ opacity: p, transform: `translateY(${(1 - p) * distance}px)`, ...style }}>
      {children}
    </div>
  );
};

/** Words rise one by one out of a mask. */
export const Words: React.FC<{
  text: string;
  delay?: number;
  stagger?: number;
  style?: React.CSSProperties;
  highlight?: Record<string, string>;
}> = ({ text, delay = 0, stagger = 3, style, highlight = {} }) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  return (
    <div style={{ display: "flex", flexWrap: "wrap", columnGap: "0.26em", ...style }}>
      {text.split(" ").map((word, i) => {
        const p = spring({ frame: frame - delay - i * stagger, fps, config: { damping: 20 } });
        return (
          <span key={i} style={{ overflow: "hidden", display: "inline-block", paddingBottom: "0.08em" }}>
            <span
              style={{
                display: "inline-block",
                transform: `translateY(${(1 - p) * 110}%)`,
                color: highlight[word] ?? undefined,
              }}
            >
              {word}
            </span>
          </span>
        );
      })}
    </div>
  );
};

export const Kicker: React.FC<{ children: React.ReactNode; delay?: number; color?: string }> = ({
  children,
  delay = 0,
  color = C.blue,
}) => (
  <FadeUp delay={delay} distance={14}>
    <div style={{ fontFamily: SANS, fontSize: 22, letterSpacing: 5, fontWeight: 600, color, textTransform: "uppercase" }}>
      {children}
    </div>
  </FadeUp>
);

export const Panel: React.FC<{
  style?: React.CSSProperties;
  glow?: string;
  children: React.ReactNode;
}> = ({ style, glow, children }) => (
  <div
    style={{
      background: C.panel,
      border: `2px solid ${glow ?? C.panelEdge}`,
      borderRadius: 22,
      boxShadow: glow ? `0 0 38px ${glow}66, inset 0 0 18px ${glow}22` : "0 18px 50px #0006",
      ...style,
    }}
  >
    {children}
  </div>
);

export const Badge: React.FC<{ color: string; children: React.ReactNode; style?: React.CSSProperties }> = ({
  color,
  children,
  style,
}) => (
  <div
    style={{
      display: "inline-flex",
      alignItems: "center",
      gap: 10,
      padding: "8px 18px",
      borderRadius: 999,
      border: `2px solid ${color}`,
      // Opaque, so lines behind a badge never show through it.
      background: `linear-gradient(${color}26, ${color}26), ${C.panel}`,
      color,
      fontFamily: MONO,
      fontSize: 24,
      whiteSpace: "nowrap",
      ...style,
    }}
  >
    {children}
  </div>
);

/** A number that counts up on an ease-out curve. */
export const Counter: React.FC<{
  to: number;
  from?: number;
  delay?: number;
  duration?: number;
  decimals?: number;
  suffix?: string;
  style?: React.CSSProperties;
}> = ({ to, from = 0, delay = 0, duration = 45, decimals = 0, suffix = "", style }) => {
  const frame = useCurrentFrame();
  const value = interpolate(frame, [delay, delay + duration], [from, to], { ...clamp, easing: easeOut });
  return (
    <span style={{ fontVariantNumeric: "tabular-nums", ...style }}>
      {value.toFixed(decimals)}
      {suffix}
    </span>
  );
};

/** A glowing dot that travels between points, on a shared frame clock. */
export const Packet: React.FC<{
  color: string;
  path: [number, number, number][]; // [frame, x, y]
  size?: number;
}> = ({ color, path, size = 26 }) => {
  const frame = useCurrentFrame();
  const frames = path.map((p) => p[0]);
  if (frame < frames[0] || frame > frames[frames.length - 1]) return null;
  const x = interpolate(frame, frames, path.map((p) => p[1]), { ...clamp, easing: Easing.inOut(Easing.cubic) });
  const y = interpolate(frame, frames, path.map((p) => p[2]), clamp);
  const fade = interpolate(frame, [frames[0], frames[0] + 6, frames[frames.length - 1] - 6, frames[frames.length - 1]], [0, 1, 1, 0], clamp);
  return (
    <div
      style={{
        position: "absolute",
        left: x - size / 2,
        top: y - size / 2,
        width: size,
        height: size,
        borderRadius: "50%",
        background: "#fff",
        border: `7px solid ${color}`,
        boxShadow: `0 0 26px 8px ${color}aa`,
        opacity: fade,
      }}
    />
  );
};

type CodeLine = { text: string; kind?: "add" | "del" | "comment" };

const KEYWORDS = /\b(from|import|def|return|for|in|if|with|as|async|await)\b/g;

const highlight = (text: string): React.ReactNode[] => {
  // Strings in amber, keywords in blue, the rest in ink. Enough for short snippets.
  const parts: React.ReactNode[] = [];
  text.split(/("[^"]*"|f"[^"]*")/g).forEach((chunk, i) => {
    if (/^f?"/.test(chunk)) {
      parts.push(<span key={i} style={{ color: "#f2c572" }}>{chunk}</span>);
      return;
    }
    let last = 0;
    for (const m of chunk.matchAll(KEYWORDS)) {
      parts.push(chunk.slice(last, m.index));
      parts.push(<span key={`${i}-${m.index}`} style={{ color: "#7fb6ff" }}>{m[0]}</span>);
      last = (m.index ?? 0) + m[0].length;
    }
    parts.push(chunk.slice(last));
  });
  return parts;
};

/** A code editor; each line slides in at its own frame. */
export const Code: React.FC<{
  lines: CodeLine[];
  starts: number[];
  title: string;
  style?: React.CSSProperties;
  strikeAt?: number;
  fontSize?: number;
}> = ({ lines, starts, title, style, strikeAt, fontSize = 27 }) => {
  const frame = useCurrentFrame();
  return (
    <Panel style={{ padding: 0, overflow: "hidden", ...style }}>
      <WindowBar title={title} />
      <div style={{ padding: "26px 34px", fontFamily: MONO, fontSize, lineHeight: 1.62, color: C.ink }}>
        {lines.map((line, i) => {
          const p = interpolate(frame, [starts[i], starts[i] + 10], [0, 1], { ...clamp, easing: easeOut });
          const struck = line.kind === "del" && strikeAt !== undefined && frame >= strikeAt;
          const strike = line.kind === "del" && strikeAt !== undefined
            ? interpolate(frame, [strikeAt, strikeAt + 14], [0, 100], clamp)
            : 0;
          const bg = line.kind === "add" ? "#34c58a1f" : line.kind === "del" && struck ? "#e8693a1c" : "transparent";
          const mark = line.kind === "add" ? "+" : line.kind === "del" ? "−" : " ";
          const markColor = line.kind === "add" ? C.green : C.orange;
          return (
            <div
              key={i}
              style={{
                opacity: p,
                transform: `translateX(${(1 - p) * -24}px)`,
                background: bg,
                margin: "0 -34px",
                padding: "0 34px",
                whiteSpace: "pre",
                position: "relative",
                color: line.kind === "comment" ? C.muted : undefined,
              }}
            >
              <span style={{ color: markColor, display: "inline-block", width: 34 }}>{line.kind ? mark : ""}</span>
              <span style={{ opacity: struck ? 0.55 : 1 }}>
                {line.kind === "comment" ? line.text : highlight(line.text)}
              </span>
              {line.kind === "del" && strike > 0 ? (
                <div style={{ position: "absolute", left: 68, top: "52%", height: 3, width: `calc((100% - 100px) * ${strike / 100})`, background: C.orange }} />
              ) : null}
            </div>
          );
        })}
      </div>
    </Panel>
  );
};

export const WindowBar: React.FC<{ title: string }> = ({ title }) => (
  <div style={{ display: "flex", alignItems: "center", gap: 12, padding: "16px 22px", background: "#0a1828", borderBottom: `1px solid ${C.line}` }}>
    {[C.orange, C.amber, C.green].map((c) => (
      <div key={c} style={{ width: 16, height: 16, borderRadius: 8, background: c }} />
    ))}
    <div style={{ flex: 1, textAlign: "center", fontFamily: SANS, fontSize: 20, color: C.muted, marginRight: 60 }}>{title}</div>
  </div>
);

/** A terminal: commands type out, output lines appear after them. */
export const Terminal: React.FC<{
  lines: { text: string; at: number; command?: boolean; color?: string; bold?: boolean }[];
  title: string;
  style?: React.CSSProperties;
  fontSize?: number;
}> = ({ lines, title, style, fontSize = 26 }) => {
  const frame = useCurrentFrame();
  return (
    <Panel style={{ padding: 0, overflow: "hidden", background: "#08111c", ...style }}>
      <WindowBar title={title} />
      <div style={{ padding: "26px 34px", fontFamily: MONO, fontSize, lineHeight: 1.6, minHeight: 200 }}>
        {lines.map((line, i) => {
          if (frame < line.at) return null;
          // The cursor sits on the last line that has started.
          const last = lines.every((other, j) => j <= i || frame < other.at);
          if (line.command) {
            const chars = Math.floor(interpolate(frame, [line.at, line.at + line.text.length * 0.9], [0, line.text.length], clamp));
            const typing = chars < line.text.length;
            return (
              <div key={i} style={{ whiteSpace: "pre", color: C.ink }}>
                <span style={{ color: C.blue }}>$ </span>
                {line.text.slice(0, chars)}
                {last && (typing || frame % 30 < 15) ? <span style={{ background: C.spray, color: C.spray }}>▍</span> : null}
              </div>
            );
          }
          const p = interpolate(frame, [line.at, line.at + 6], [0, 1], clamp);
          return (
            <div key={i} style={{ whiteSpace: "pre", opacity: p, color: line.color ?? C.ink2, fontWeight: line.bold ? 600 : 400 }}>
              {line.text}
            </div>
          );
        })}
      </div>
    </Panel>
  );
};

/** The backdrop shared by every scene: deep water, a drifting grid, slow waves. */
export const Backdrop: React.FC = () => {
  const frame = useCurrentFrame();
  const drift = (frame * 0.35) % 48;
  const wave = (offset: number, amp: number, y: number, speed: number) => {
    const shift = (frame * speed) % 320;
    let d = `M ${-320 - shift} ${STAGE_HEIGHT}`;
    for (let x = -320; x <= WIDTH + 320; x += 16) {
      d += ` L ${x - shift} ${y + amp * Math.sin(((x + offset) / 320) * Math.PI * 2)}`;
    }
    return `${d} L ${WIDTH + 320} ${STAGE_HEIGHT} Z`;
  };
  return (
    <AbsoluteFill style={{ background: `linear-gradient(170deg, ${C.bgTop} 0%, #081627 55%, ${C.bgBottom} 100%)` }}>
      <AbsoluteFill
        style={{
          backgroundImage: "radial-gradient(#8fb8e01c 1.6px, transparent 1.6px)",
          backgroundSize: "48px 48px",
          backgroundPosition: `${drift}px ${drift / 2}px`,
        }}
      />
      <AbsoluteFill style={{ background: "radial-gradient(ellipse at 50% 40%, transparent 40%, #02060b 100%)", opacity: 0.8 }} />
      <svg width={WIDTH} height={STAGE_HEIGHT} style={{ position: "absolute", inset: 0 }}>
        <path d={wave(0, 9, STAGE_HEIGHT - 46, 0.9)} fill="#0f3a5c" fillOpacity={0.45} />
        <path d={wave(110, 7, STAGE_HEIGHT - 32, -1.4)} fill="#11507a" fillOpacity={0.5} />
        <path d={wave(220, 5, STAGE_HEIGHT - 18, 2.0)} fill="#1a6aa0" fillOpacity={0.55} />
      </svg>
    </AbsoluteFill>
  );
};

/** The Breakwater mark: a glowing wall. */
export const Wall: React.FC<{ height: number; glow?: number; style?: React.CSSProperties }> = ({ height, glow = 1, style }) => (
  <div
    style={{
      width: 22,
      height,
      borderRadius: 11,
      background: `linear-gradient(90deg, ${C.spray}, ${C.blue} 55%, #1b4f8a)`,
      boxShadow: `0 0 ${30 * glow}px ${10 * glow}px ${C.blue}88`,
      ...style,
    }}
  />
);

export const text = (size: number, weight = 400, color: string = C.ink): React.CSSProperties => ({
  fontFamily: SANS,
  fontSize: size,
  fontWeight: weight,
  color,
  letterSpacing: size > 60 ? -1.5 : 0,
});
