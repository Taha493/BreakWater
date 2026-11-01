import React from "react";
import { Composition } from "remotion";
import { HEIGHT, WIDTH } from "./theme";
import { FPS, TOTAL_FRAMES } from "./timeline";
import { BreakwaterVideo } from "./Video";

export const RemotionRoot: React.FC = () => (
  <Composition
    id="Breakwater"
    component={BreakwaterVideo}
    durationInFrames={TOTAL_FRAMES}
    fps={FPS}
    width={WIDTH}
    height={HEIGHT}
  />
);
