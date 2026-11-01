import React from "react";
import { AbsoluteFill, interpolate, useCurrentFrame } from "remotion";
import { Badge, clamp, Counter, easeOut, FadeUp, Kicker, Panel, text, Words } from "../components";
import { C, SANS } from "../theme";

const MILESTONES = [
  ["M1", "Proxy & auth", "hashed keys, redacted events"],
  ["M2", "Detectors", "normalizer, RE2 rules, policy"],
  ["M3", "RAG & tools", "document scanner, tool guard"],
  ["M4", "Red team", "75 attacks, CI gate"],
  ["M5", "Layers & UI", "classifier, judge, dashboard"],
];
const LINE_L = 230, LINE_R = 1690, LINE_Y = 360;
const FILL_FROM = 176, FILL_TO = 382;

const STATS = [
  [886, "automated tests"],
  [66, "Docker smoke checks"],
  [75, "attacks in the red team"],
  [100, "benign test cases"],
] as const;

const STACK = ["Python 3.12", "FastAPI", "Postgres", "RE2", "ONNX Runtime", "React", "Docker"];

export const Made: React.FC = () => {
  const frame = useCurrentFrame();
  const fill = interpolate(frame, [FILL_FROM, FILL_TO], [0, 1], { ...clamp, easing: easeOut });
  return (
    <AbsoluteFill style={{ padding: "72px 110px" }}>
      <Kicker>How it was made</Kicker>
      <Words text="Spec first. Five milestones. Each one tested." delay={6} style={{ ...text(60, 700), marginTop: 16 }} />
      <div style={{ position: "absolute", left: LINE_L, top: LINE_Y - 3, width: LINE_R - LINE_L, height: 6, borderRadius: 3, background: C.line, opacity: interpolate(frame, [20, 40], [0, 1], clamp) }} />
      <div style={{ position: "absolute", left: LINE_L, top: LINE_Y - 3, width: (LINE_R - LINE_L) * fill, height: 6, borderRadius: 3, background: C.blue, boxShadow: `0 0 18px ${C.blue}` }} />
      {MILESTONES.map(([tag, title, sub], i) => {
        const x = LINE_L + ((LINE_R - LINE_L) * i) / (MILESTONES.length - 1);
        const lit = fill >= i / (MILESTONES.length - 1) - 0.001;
        const pop = lit ? 1 : 0.6;
        return (
          <React.Fragment key={tag}>
            <div style={{ position: "absolute", left: x - 70, top: LINE_Y - 82, width: 140, textAlign: "center", ...text(30, 800, lit ? C.blue : C.muted), opacity: interpolate(frame, [24 + i * 6, 40 + i * 6], [0, 1], clamp) }}>{tag}</div>
            <div
              style={{
                position: "absolute",
                left: x - 20,
                top: LINE_Y - 20,
                width: 40,
                height: 40,
                borderRadius: 20,
                background: lit ? C.blue : C.panel,
                border: `4px solid ${lit ? C.spray : C.panelEdge}`,
                boxShadow: lit ? `0 0 30px ${C.blue}` : "none",
                transform: `scale(${pop})`,
                opacity: interpolate(frame, [24 + i * 6, 40 + i * 6], [0, 1], clamp),
              }}
            />
            <div style={{ position: "absolute", left: x - 160, top: LINE_Y + 40, width: 320, textAlign: "center", opacity: lit ? 1 : 0.35 }}>
              <div style={text(32, 700)}>{title}</div>
              <div style={{ fontFamily: SANS, fontSize: 23, color: C.muted, marginTop: 6 }}>{sub}</div>
            </div>
          </React.Fragment>
        );
      })}
      <div style={{ position: "absolute", left: 110, right: 110, top: 560, display: "flex", gap: 30 }}>
        {STATS.map(([n, label], i) =>
          frame >= 386 + i * 10 ? (
            <FadeUp key={label} delay={386 + i * 10} style={{ flex: 1 }}>
              <Panel style={{ padding: "24px 30px" }}>
                <div style={text(64, 800)}>
                  <Counter to={n} delay={386 + i * 10} duration={40} />
                </div>
                <div style={{ fontFamily: SANS, fontSize: 25, color: C.ink2, marginTop: 2 }}>{label}</div>
              </Panel>
            </FadeUp>
          ) : null,
        )}
      </div>
      <div style={{ position: "absolute", left: 110, right: 110, top: 776, display: "flex", gap: 16, flexWrap: "wrap", alignItems: "center" }}>
        {STACK.map((name, i) =>
          frame >= 604 + i * 5 ? (
            <FadeUp key={name} delay={604 + i * 5} distance={14}>
              <Badge color={C.ink2} style={{ fontSize: 22, padding: "6px 16px" }}>{name}</Badge>
            </FadeUp>
          ) : null,
        )}
        {frame >= 650 ? (
          <FadeUp delay={650} distance={14}>
            <Badge color={C.blue} style={{ fontSize: 22, padding: "6px 16px" }}>built with Claude Code</Badge>
          </FadeUp>
        ) : null}
      </div>
    </AbsoluteFill>
  );
};
