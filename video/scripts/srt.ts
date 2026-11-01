// Writes out/breakwater.srt from the captions in src/timeline.ts (node strips the types).
import { mkdirSync, writeFileSync } from "node:fs";
import { CAPTIONS, FPS } from "../src/timeline.ts";

const stamp = (frame: number): string => {
  const ms = Math.round((frame / FPS) * 1000);
  const pad = (n: number, w = 2) => String(n).padStart(w, "0");
  return `${pad(Math.floor(ms / 3600000))}:${pad(Math.floor(ms / 60000) % 60)}:${pad(Math.floor(ms / 1000) % 60)},${pad(ms % 1000, 3)}`;
};

// A caption ends where the next one starts, as in the video.
const srt = CAPTIONS.map((c, i) => {
  const end = Math.min(c.to, CAPTIONS[i + 1]?.from ?? c.to);
  return `${i + 1}\n${stamp(c.from)} --> ${stamp(end)}\n${c.text}\n`;
}).join("\n");
mkdirSync("out", { recursive: true });
writeFileSync("out/breakwater.srt", srt);
console.log(`wrote out/breakwater.srt (${CAPTIONS.length} captions)`);
