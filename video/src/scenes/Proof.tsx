import React from "react";
import { AbsoluteFill, interpolate, useCurrentFrame } from "remotion";
import { Badge, clamp, Counter, easeOut, FadeUp, Kicker, Panel, text, Words } from "../components";
import { C, MONO, SANS } from "../theme";

const ROWS = [
  { label: "Without Breakwater", sub: "the model alone", value: 98, decimals: 0, fp: "–", p50: "–", color: C.orange },
  { label: "Rules only", sub: "layer 1, always on", value: 44, decimals: 0, fp: "0%", p50: "22 ms", color: C.blue },
  { label: "Rules + LLM judge", sub: "judge on borderline text", value: 22.7, decimals: 1, fp: "0%", p50: "31 ms*", color: C.blue },
  { label: "Rules + classifier", sub: "layer 2, DeBERTa", value: 1.3, decimals: 1, fp: "7%", p50: "143 ms", color: C.blue },
];
const BAR_X = 640, BAR_W = 780, TOP = 268, ROW = 104;

const CHECKS = [
  { label: "lint · types", ok: true, at: 404 },
  { label: "886 tests", ok: true, at: 420 },
  { label: "red team: indirect injection 0% → 12%", ok: false, at: 440 },
];

export const Proof: React.FC = () => {
  const frame = useCurrentFrame();
  return (
    <AbsoluteFill style={{ padding: "72px 110px" }}>
      <Kicker>Measured, not claimed</Kicker>
      <Words text="Attacks that still succeed" delay={6} style={{ ...text(64, 700), marginTop: 18 }} />
      <FadeUp delay={20}>
        <div style={{ fontFamily: SANS, fontSize: 25, color: C.muted, marginTop: 8 }}>
          75 attacks × 2 variants · 100 benign prompts · seed 1 · simulated model that obeys any injected instruction
        </div>
      </FadeUp>
      <div style={{ position: "absolute", left: 1480, top: TOP - 46, width: 180, textAlign: "center", whiteSpace: "nowrap", ...text(22, 500, C.muted), opacity: interpolate(frame, [190, 210], [0, 1], clamp) }}>false positives</div>
      <div style={{ position: "absolute", left: 1660, top: TOP - 46, width: 150, textAlign: "center", whiteSpace: "nowrap", ...text(22, 500, C.muted), opacity: interpolate(frame, [190, 210], [0, 1], clamp) }}>added p50</div>
      {ROWS.map((row, i) => {
        const delay = 40 + i * 36;
        const grow = interpolate(frame, [delay, delay + 40], [0, 1], { ...clamp, easing: easeOut });
        const width = Math.max(4, (BAR_W * row.value) / 100) * grow;
        const y = TOP + i * ROW;
        const side = interpolate(frame, [200 + i * 8, 216 + i * 8], [0, 1], clamp);
        return (
          <React.Fragment key={row.label}>
            <div style={{ position: "absolute", left: 110, top: y - 6, opacity: interpolate(frame, [delay - 10, delay + 6], [0, 1], clamp) }}>
              <div style={text(34, 700)}>{row.label}</div>
              <div style={text(22, 400, C.muted)}>{row.sub}</div>
            </div>
            <div style={{ position: "absolute", left: BAR_X, top: y, width, height: 46, borderRadius: 6, background: row.color, boxShadow: `0 0 30px ${row.color}44` }} />
            <div style={{ position: "absolute", left: BAR_X + width + 18, top: y + 2, ...text(36, 800), opacity: grow }}>
              <Counter to={row.value} delay={delay} duration={40} decimals={row.decimals} suffix="%" />
            </div>
            <div style={{ position: "absolute", left: 1500, top: y + 4, width: 140, textAlign: "center", ...text(32, 600, C.ink2), opacity: side }}>{row.fp}</div>
            <div style={{ position: "absolute", left: 1660, top: y + 4, width: 150, textAlign: "center", ...text(32, 600, C.ink2), opacity: side }}>{row.p50}</div>
          </React.Fragment>
        );
      })}
      <div style={{ position: "absolute", left: 110, top: TOP + 4 * ROW - 6, fontFamily: SANS, fontSize: 21, color: C.muted, opacity: interpolate(frame, [220, 240], [0, 1], clamp) }}>
        * 31 ms when the judge is not called, about 860 ms when it is.
      </div>
      <div style={{ position: "absolute", left: 110, right: 110, top: 720 }}>
        {frame >= 396 ? (
          <FadeUp delay={396}>
            <Panel style={{ padding: "22px 30px", display: "flex", alignItems: "center", gap: 26 }}>
              <div style={{ fontFamily: MONO, fontSize: 26, color: C.ink2 }}>CI</div>
              {CHECKS.map((c) =>
                frame >= c.at ? (
                  <FadeUp key={c.label} delay={c.at} distance={16}>
                    <Badge color={c.ok ? C.green : C.orange}>
                      {c.ok ? "✓" : "✕"} {c.label}
                    </Badge>
                  </FadeUp>
                ) : null,
              )}
              <div style={{ flex: 1 }} />
              {frame >= 470 ? (
                <FadeUp delay={470} distance={16}>
                  <div style={text(30, 700, C.orange)}>build fails</div>
                </FadeUp>
              ) : null}
            </Panel>
          </FadeUp>
        ) : null}
      </div>
    </AbsoluteFill>
  );
};
