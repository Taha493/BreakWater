import { loadFont } from "@remotion/google-fonts/Inter";
import { loadFont as loadMono } from "@remotion/google-fonts/JetBrainsMono";

export const SANS = loadFont("normal", {
  weights: ["400", "500", "600", "700", "800"],
  subsets: ["latin"],
}).fontFamily;
export const MONO = loadMono("normal", { weights: ["400", "600"], subsets: ["latin"] }).fontFamily;

export const WIDTH = 1920;
export const HEIGHT = 1080;
// Scenes draw only inside the stage; the band below it belongs to the captions alone.
export const STAGE_HEIGHT = 900;
export const CAPTION_HEIGHT = HEIGHT - STAGE_HEIGHT;

// The README's palette: blue for traffic that passes, orange for attacks, amber for
// borderline, green for a safe outcome.
export const C = {
  bgTop: "#050c17",
  bgBottom: "#0b2236",
  captionBand: "#03070d",
  ink: "#eaf3ff",
  ink2: "#a9c1da",
  muted: "#5f7d99",
  line: "#1f3d5a",
  panel: "#0d1e31",
  panelEdge: "#2c5579",
  blue: "#3f8fe8",
  orange: "#e8693a",
  amber: "#e0a526",
  green: "#34c58a",
  spray: "#9fd6ff",
};
