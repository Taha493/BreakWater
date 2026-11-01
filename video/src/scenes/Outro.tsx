import React from "react";
import { AbsoluteFill, interpolate, useCurrentFrame } from "remotion";
import { clamp, easeOut, FadeUp, text, useEnter, Wall } from "../components";
import { C, MONO } from "../theme";

export const Outro: React.FC = () => {
  const frame = useCurrentFrame();
  const rise = useEnter(4, 14);
  const reveal = interpolate(frame, [12, 40], [100, 0], { ...clamp, easing: easeOut });
  const fadeToBlack = interpolate(frame, [236, 268], [0, 1], clamp);
  return (
    <AbsoluteFill style={{ alignItems: "center", justifyContent: "center" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 38 }}>
        <Wall height={150 * rise} glow={1 + 0.3 * Math.sin(frame / 8)} />
        <div style={{ clipPath: `inset(-20% ${reveal}% -20% 0)`, ...text(130, 800), letterSpacing: -3, lineHeight: 1 }}>Breakwater</div>
      </div>
      <FadeUp delay={36} style={{ marginTop: 34 }}>
        <div style={text(42, 400, C.ink2)}>The LLM firewall that attacks itself.</div>
      </FadeUp>
      <FadeUp delay={60} style={{ marginTop: 50 }}>
        <div style={{ fontFamily: MONO, fontSize: 38, color: C.ink, padding: "14px 30px", borderRadius: 16, border: `2px solid ${C.panelEdge}`, background: C.panel }}>
          github.com/Taha493/BreakWater
        </div>
      </FadeUp>
      <AbsoluteFill style={{ background: "#000", opacity: fadeToBlack }} />
    </AbsoluteFill>
  );
};
