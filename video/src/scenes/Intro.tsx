import React from "react";
import { AbsoluteFill, interpolate, Sequence, useCurrentFrame } from "remotion";
import { clamp, easeOut, FadeUp, text, useEnter, Wall, Words } from "../components";
import { C, SANS } from "../theme";

const Spray: React.FC<{ at: number }> = ({ at }) => {
  const frame = useCurrentFrame();
  const t = interpolate(frame, [at, at + 26], [0, 1], { ...clamp, easing: easeOut });
  if (frame < at || t >= 1) return null;
  return (
    <>
      {Array.from({ length: 14 }, (_, i) => {
        const angle = (i / 14) * Math.PI * 2;
        const r = 40 + t * (120 + (i % 3) * 40);
        return (
          <div
            key={i}
            style={{
              position: "absolute",
              left: Math.cos(angle) * r - 5,
              top: Math.sin(angle) * r * 0.7 - 5,
              width: i % 2 ? 12 : 8,
              height: i % 2 ? 12 : 8,
              borderRadius: "50%",
              background: C.spray,
              opacity: 1 - t,
            }}
          />
        );
      })}
    </>
  );
};

const Logo: React.FC = () => {
  const frame = useCurrentFrame();
  const rise = useEnter(0, 12);
  const reveal = interpolate(frame, [14, 46], [100, 0], { ...clamp, easing: easeOut });
  const spacing = interpolate(frame, [14, 60], [24, -3], { ...clamp, easing: easeOut });
  return (
    <AbsoluteFill style={{ alignItems: "center", justifyContent: "center" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 46 }}>
        <div style={{ position: "relative" }}>
          <Wall height={210 * rise} glow={1.2} />
          <div style={{ position: "absolute", left: 11, top: 105 }}>
            <Spray at={10} />
          </div>
        </div>
        <div style={{ clipPath: `inset(-20% ${reveal}% -20% 0)` }}>
          <div style={{ ...text(176, 800), letterSpacing: spacing, lineHeight: 1 }}>Breakwater</div>
        </div>
      </div>
      <FadeUp delay={44} style={{ marginTop: 40 }}>
        <div style={text(46, 400, C.ink2)}>The LLM firewall that attacks itself.</div>
      </FadeUp>
    </AbsoluteFill>
  );
};

export const Intro: React.FC = () => {
  const frame = useCurrentFrame();
  const out = interpolate(frame, [100, 120], [0, 1], { ...clamp, easing: easeOut });
  return (
    <AbsoluteFill>
      <AbsoluteFill
        style={{
          alignItems: "center",
          justifyContent: "center",
          opacity: 1 - out,
          transform: `translateY(${-50 * out}px) scale(${1 - out * 0.04})`,
        }}
      >
        <Words
          text="Every LLM app reads text it didn't write."
          delay={8}
          stagger={4}
          style={{ ...text(84, 700), justifyContent: "center", maxWidth: 1800 }}
          highlight={{ "didn't": C.orange, "write.": C.orange }}
        />
        <FadeUp delay={44} style={{ marginTop: 34 }}>
          <div style={{ display: "flex", gap: 22, fontFamily: SANS, fontSize: 30, color: C.muted }}>
            <span>user messages</span>·<span>documents</span>·<span>web pages</span>·<span>tool results</span>
          </div>
        </FadeUp>
      </AbsoluteFill>
      <Sequence from={116}>
        <Logo />
      </Sequence>
    </AbsoluteFill>
  );
};
