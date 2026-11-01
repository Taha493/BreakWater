// Scene lengths and the captions, in frames at 30 fps. No imports, so `node` can read this
// file directly (scripts/srt.ts writes the captions as an .srt file).

export const FPS = 30;
export const TRANSITION = 20;

export const SCENES = [
  { id: "intro", frames: 270 },
  { id: "problem", frames: 1020 },
  { id: "solution", frames: 1140 },
  { id: "proof", frames: 630 },
  { id: "integrate", frames: 960 },
  { id: "made", frames: 780 },
  { id: "outro", frames: 270 },
] as const;

export type SceneId = (typeof SCENES)[number]["id"];

/** First frame of each scene: scenes overlap by one transition. */
export const SCENE_START: Record<SceneId, number> = (() => {
  const starts = {} as Record<SceneId, number>;
  let at = 0;
  for (const scene of SCENES) {
    starts[scene.id] = at;
    at += scene.frames - TRANSITION;
  }
  return starts;
})();

export const TOTAL_FRAMES =
  SCENES.reduce((sum, scene) => sum + scene.frames, 0) - TRANSITION * (SCENES.length - 1);

/** [scene, from, to, text]: from and to are frames inside the scene. */
const RELATIVE: [SceneId, number, number, string][] = [
  ["intro", 8, 118, "Every LLM app reads text it didn't write."],
  ["intro", 124, 262, "This is Breakwater: a firewall for LLM apps that attacks itself to prove it works."],

  ["problem", 22, 150, "Here's the problem: a model can't tell your instructions from the text it reads."],
  ["problem", 152, 300, "One hidden line in a document, and the assistant obeys the attacker instead of you."],
  ["problem", 306, 416, "Attacks on LLM apps come in four shapes."],
  ["problem", 420, 528, "Direct injection: a user simply tells the model to ignore its rules."],
  ["problem", 530, 638, "Indirect injection: instructions hidden in PDFs, web pages or tool results."],
  ["problem", 640, 748, "Data leakage: secrets and personal data slipping out in prompts or replies."],
  ["problem", 750, 858, "Tool abuse: tricking an agent into calling its tools for the attacker."],
  ["problem", 862, 1012, "Against an unprotected app, 98% of our 75 test attacks succeed."],

  ["solution", 22, 176, "Breakwater sits between your app and the model. Every request and reply passes through it."],
  ["solution", 180, 344, "It checks text in layers, cheapest first: normalising, fast rules, an optional classifier, then an LLM judge."],
  ["solution", 350, 562, "A normal question goes straight through. If the reply leaks a key, it is redacted on the way back."],
  ["solution", 570, 692, "An obvious injection is stopped by the rules, in about 20 milliseconds."],
  ["solution", 700, 872, "Borderline text goes to the LLM judge, which makes the call. Here it blocks with 0.99 confidence."],
  ["solution", 880, 1132, "The same checks protect documents before they are indexed and agent tool calls before they run."],

  ["proof", 22, 182, "We built a red team into the project: 75 attacks, two variants each, and 100 harmless prompts."],
  ["proof", 186, 400, "Rules alone cut attack success from 98% to 44%. With the classifier it falls to 1.3%, at 7% false positives."],
  ["proof", 404, 624, "In CI, the same harness fails the build if a change lets more attacks through."],

  ["integrate", 22, 236, "To use it, run Breakwater next to your app: one command starts the gateway, database and dashboard."],
  ["integrate", 244, 476, "Then point your app at it. Any OpenAI-compatible client works: change the base URL and the key."],
  ["integrate", 484, 716, "For RAG and agents, the Python SDK scans documents, marks retrieved text as untrusted, and guards tool calls."],
  ["integrate", 724, 954, "And run the red team against your own app in CI, so a weaker policy can never ship unnoticed."],

  ["made", 22, 172, "Breakwater was built spec first, in five milestones, each one tested before the next began."],
  ["made", 176, 382, "Proxy and auth, detectors, document and tool protection, the red team, then the classifier, judge and dashboard."],
  ["made", 386, 600, "886 automated tests and 66 Docker smoke checks, and every number in this video comes from the harness."],
  ["made", 604, 776, "Python, FastAPI, Postgres, RE2, ONNX Runtime and React, built with Claude Code."],

  ["outro", 22, 266, "Breakwater: the LLM firewall that attacks itself. Find it on GitHub."],
];

export type Caption = { from: number; to: number; text: string };

export const CAPTIONS: Caption[] = RELATIVE.map(([scene, from, to, text]) => ({
  from: SCENE_START[scene] + from,
  to: SCENE_START[scene] + to,
  text,
}));
