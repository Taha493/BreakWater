import React from "react";
import { AbsoluteFill, interpolate, useCurrentFrame } from "remotion";
import { linearTiming, TransitionSeries } from "@remotion/transitions";
import { fade } from "@remotion/transitions/fade";
import { slide } from "@remotion/transitions/slide";
import { Backdrop, clamp } from "./components";
import { Integrate } from "./scenes/Integrate";
import { Intro } from "./scenes/Intro";
import { Made } from "./scenes/Made";
import { Outro } from "./scenes/Outro";
import { Problem } from "./scenes/Problem";
import { Proof } from "./scenes/Proof";
import { Solution } from "./scenes/Solution";
import { C, CAPTION_HEIGHT, SANS, STAGE_HEIGHT, WIDTH } from "./theme";
import { CAPTIONS, SCENES, TRANSITION } from "./timeline";

const SCENE_COMPONENTS = {
  intro: Intro,
  problem: Problem,
  solution: Solution,
  proof: Proof,
  integrate: Integrate,
  made: Made,
  outro: Outro,
};

// Slides read as a camera move between chapters; fades elsewhere.
const SLIDE_INTO = new Set(["solution", "made"]);

/** The bottom band: captions only, always in the same place. */
const Captions: React.FC = () => {
  const frame = useCurrentFrame();
  const current = CAPTIONS.filter((c) => frame >= c.from && frame < c.to).at(-1);
  const opacity = current
    ? interpolate(frame, [current.from, current.from + 6, current.to - 6, current.to], [0, 1, 1, 0], clamp)
    : 0;
  return (
    <div
      style={{
        position: "absolute",
        left: 0,
        top: STAGE_HEIGHT,
        width: WIDTH,
        height: CAPTION_HEIGHT,
        background: C.captionBand,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
      }}
    >
      {current ? (
        <div
          style={{
            maxWidth: 1560,
            fontFamily: SANS,
            fontSize: 40,
            fontWeight: 500,
            lineHeight: 1.35,
            color: "#ffffff",
            textAlign: "center",
            textWrap: "balance",
            opacity,
          }}
        >
          {current.text}
        </div>
      ) : null}
    </div>
  );
};

export const BreakwaterVideo: React.FC = () => (
  <AbsoluteFill style={{ background: C.captionBand }}>
    {/* Code font ligatures would turn <!-- and --> into arrows. */}
    <style>{"* { font-variant-ligatures: none; font-feature-settings: 'liga' 0, 'calt' 0; }"}</style>
    {/* Everything except captions draws inside this clipped stage. */}
    <div style={{ position: "absolute", left: 0, top: 0, width: WIDTH, height: STAGE_HEIGHT, overflow: "hidden" }}>
      <Backdrop />
      <TransitionSeries>
        {SCENES.map((scene, i) => {
          const Scene = SCENE_COMPONENTS[scene.id];
          return (
            <React.Fragment key={scene.id}>
              {i > 0 ? (
                <TransitionSeries.Transition
                  presentation={SLIDE_INTO.has(scene.id) ? slide({ direction: "from-right" }) : fade({ shouldFadeOutExitingScene: true })}
                  timing={linearTiming({ durationInFrames: TRANSITION })}
                />
              ) : null}
              <TransitionSeries.Sequence durationInFrames={scene.frames}>
                <Scene />
              </TransitionSeries.Sequence>
            </React.Fragment>
          );
        })}
      </TransitionSeries>
    </div>
    <Captions />
  </AbsoluteFill>
);
