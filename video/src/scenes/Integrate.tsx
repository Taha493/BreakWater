import React from "react";
import { AbsoluteFill, interpolate, Sequence, useCurrentFrame } from "remotion";
import { clamp, Code, easeOut, FadeUp, Kicker, Terminal, text } from "../components";
import { C, SANS } from "../theme";

const STEP = 240;
const STEPS = [
  ["Run it", "Docker Compose: gateway, Postgres, dashboard"],
  ["Point your app at it", "change the base URL and the key"],
  ["Protect RAG and agents", "the Python SDK"],
  ["Keep attacking it", "the red team in your CI"],
];

/** Fades a step's panel in and out inside its own window. */
const StepPanel: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const frame = useCurrentFrame();
  const o = interpolate(frame, [0, 14, STEP - 12, STEP], [0, 1, 1, 0], clamp);
  const y = interpolate(frame, [0, 18], [30, 0], { ...clamp, easing: easeOut });
  return <div style={{ position: "absolute", left: 760, right: 110, top: 150, opacity: o, transform: `translateY(${y}px)` }}>{children}</div>;
};

const RunIt = () => (
  <Terminal
    title="terminal"
    lines={[
      { text: "git clone https://github.com/Taha493/BreakWater", at: 12, command: true },
      { text: "cd BreakWater && cp .env.example .env", at: 64, command: true },
      { text: "docker compose up", at: 112, command: true },
      { text: "✔ gateway     healthy   http://localhost:8000", at: 150, color: C.green },
      { text: "✔ postgres    healthy", at: 158, color: C.green },
      { text: "✔ dashboard   ready     http://localhost:8080", at: 166, color: C.green },
    ]}
  />
);

const PointIt = () => (
  <Code
    title="app.py"
    strikeAt={60}
    starts={[8, 14, 22, 30, 36, 86, 96, 106]}
    lines={[
      { text: "from openai import OpenAI" },
      { text: "" },
      { text: "client = OpenAI(" },
      { text: "    base_url=\"https://api.openai.com/v1\",", kind: "del" },
      { text: "    api_key=os.environ[\"OPENAI_API_KEY\"],", kind: "del" },
      { text: "    base_url=\"https://breakwater.internal/v1\",", kind: "add" },
      { text: "    api_key=os.environ[\"BREAKWATER_KEY\"],", kind: "add" },
      { text: ")" },
    ]}
  />
);

const ProtectIt = () => (
  <Code
    title="rag_agent.py"
    fontSize={23}
    starts={[8, 14, 20, 28, 34, 42, 50, 58, 66, 74, 82, 90, 98]}
    lines={[
      { text: "import breakwater_client as bw" },
      { text: "" },
      { text: "gw = bw.GatewayClient(\"https://breakwater.internal\", api_key=KEY)" },
      { text: "# ingest: index only the chunks Breakwater allows", kind: "comment" },
      { text: "result = gw.scan_chunks(chunks, doc_id=\"handbook.pdf\")" },
      { text: "" },
      { text: "# ask: retrieved text is marked as data, not instructions", kind: "comment" },
      { text: "prompt = f\"Context: {bw.harden_context(top_k)} Question: {q}\"" },
      { text: "" },
      { text: "# agents: every tool call is checked before it runs", kind: "comment" },
      { text: "@bw.guarded_tool(gw, agent_id=\"support-agent\")" },
      { text: "def send_email(to: str, body: str) -> None: ..." },
      { text: "" },
    ]}
  />
);

const TestIt = () => (
  <Terminal
    title="CI: red team"
    fontSize={24}
    lines={[
      { text: "breakwater redteam run --target my_app --fail-on-regression", at: 12, command: true },
      { text: "category             unprotected  protected", at: 80, color: C.muted },
      { text: "direct_injection          100.0%       2.5%", at: 88 },
      { text: "indirect_injection         96.0%      12.0%", at: 96, color: C.amber },
      { text: "regression in: indirect_injection", at: 120, color: C.orange },
      { text: "exit 1 · the change does not ship", at: 140, color: C.orange, bold: true },
    ]}
  />
);

export const Integrate: React.FC = () => {
  const frame = useCurrentFrame();
  const active = Math.min(3, Math.floor(frame / STEP));
  return (
    <AbsoluteFill style={{ padding: "72px 110px" }}>
      <Kicker>Add it to your project</Kicker>
      <div style={{ position: "absolute", left: 110, top: 160, width: 600 }}>
        {STEPS.map(([title, sub], i) => {
          const on = i === active;
          const done = i < active;
          const lit = interpolate(frame, [i * STEP, i * STEP + 12], [0, 1], clamp);
          return (
            <FadeUp key={title} delay={4 + i * 8}>
              <div style={{ display: "flex", gap: 26, alignItems: "center", marginBottom: 46, opacity: on ? 1 : done ? 0.55 : 0.35 }}>
                <div
                  style={{
                    width: 72,
                    height: 72,
                    borderRadius: 36,
                    flexShrink: 0,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    ...text(34, 800, on ? "#04101d" : C.ink),
                    background: on ? C.blue : "transparent",
                    border: `3px solid ${on || done ? C.blue : C.panelEdge}`,
                    boxShadow: on ? `0 0 ${30 * lit}px ${C.blue}aa` : "none",
                  }}
                >
                  {done ? "✓" : i + 1}
                </div>
                <div>
                  <div style={text(38, 700)}>{title}</div>
                  <div style={{ fontFamily: SANS, fontSize: 25, color: C.muted, marginTop: 4 }}>{sub}</div>
                </div>
              </div>
            </FadeUp>
          );
        })}
      </div>
      <Sequence durationInFrames={STEP}>
        <StepPanel><RunIt /></StepPanel>
      </Sequence>
      <Sequence from={STEP} durationInFrames={STEP}>
        <StepPanel><PointIt /></StepPanel>
      </Sequence>
      <Sequence from={STEP * 2} durationInFrames={STEP}>
        <StepPanel><ProtectIt /></StepPanel>
      </Sequence>
      <Sequence from={STEP * 3} durationInFrames={STEP}>
        <StepPanel><TestIt /></StepPanel>
      </Sequence>
    </AbsoluteFill>
  );
};
