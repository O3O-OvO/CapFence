import React from "react";
import { AbsoluteFill, Composition, Sequence, interpolate, useCurrentFrame } from "remotion";
import { registerRoot } from "remotion";

const items = [
  ["network.connect", "dynamic host", "mcp.json:6", "#ff6b6b"],
  ["credential.read", "embedded secret", "mcp.json:7", "#ffb86b"],
  ["filesystem.read", "/home/runner/.ssh", "mcp.json:8", "#bd93f9"],
  ["process.execute", "downloaded script", "mcp.json:4", "#ff79c6"],
] as const;

function Card({ title, children, color = "#8be9fd" }: { title: string; children: React.ReactNode; color?: string }) {
  return <div style={{ background: "#182235", border: `1px solid ${color}55`, borderRadius: 20, padding: 28, boxShadow: `0 15px 50px ${color}12` }}><div style={{ color, fontSize: 22, fontWeight: 700, marginBottom: 16 }}>{title}</div>{children}</div>;
}

function App() {
  const frame = useCurrentFrame();
  const opacity = interpolate(frame, [0, 20], [0, 1], { extrapolateRight: "clamp" });
  const stage = Math.floor(frame / 90);
  return <AbsoluteFill style={{ background: "#0b1020", color: "#f8f8f2", fontFamily: "Arial, sans-serif", padding: 70, opacity }}>
    <div style={{ display: "flex", justifyContent: "space-between", color: "#6272a4", fontSize: 20 }}><b>CAPFENCE</b><span>STATIC PERMISSION REVIEW</span></div>
    <div style={{ marginTop: 70 }}>
      <h1 style={{ fontSize: 72, margin: 0, letterSpacing: -3 }}>{stage === 0 ? "MCP permissions changed" : stage === 1 ? "Safe → dangerous" : stage === 2 ? "A reviewable permission diff" : "Block before merge"}</h1>
      <p style={{ color: "#aab4d0", fontSize: 28, marginTop: 20 }}>{stage === 0 ? "See what an agent can do—and what a pull request adds." : "Same server configuration. New capabilities. Human-readable evidence."}</p>
    </div>
    {stage === 0 && <div style={{ display: "flex", gap: 30, marginTop: 90 }}><Card title="SAFE CONFIGURATION"><pre style={{ color: "#50fa7b", fontSize: 24 }}>{`npx server@1.0.0\nGITHUB_TOKEN: \"$GITHUB_TOKEN\"`}</pre></Card><div style={{ fontSize: 70, color: "#ffb86c", alignSelf: "center" }}>→</div><Card title="DANGEROUS CHANGE" color="#ff6b6b"><pre style={{ color: "#ff6b6b", fontSize: 24 }}>{`bash -c \"curl ... | bash\"\nOPENAI_API_KEY: \"sk-[redacted]\"`}</pre></Card></div>}
    {stage === 1 && <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 22, marginTop: 70 }}>{items.map(([kind, scope, loc, color]) => <Card key={kind} title={`ADDED  ${kind}`} color={color}><div style={{ fontSize: 30 }}>{scope}</div><div style={{ color: "#aab4d0", fontSize: 20, marginTop: 14 }}>{loc}</div></Card>)}</div>}
    {stage === 2 && <div style={{ marginTop: 70 }}><Card title="CAPFENCE DIFF  •  POLICY VIOLATIONS" color="#ffb86c"><div style={{ display: "flex", flexDirection: "column", gap: 22 }}>{["CRITICAL  CF-EXEC-002  downloaded script piped to Bash", "CRITICAL  CF-CRED-002  embedded credential", "HIGH      CF-MCP-001   dynamic remote endpoint"].map((x, i) => <div key={x} style={{ fontFamily: "monospace", fontSize: 25, color: i < 2 ? "#ff6b6b" : "#ffb86c" }}>{x}</div>)}</div></Card></div>}
    {stage >= 3 && <div style={{ marginTop: 100, textAlign: "center" }}><div style={{ fontSize: 100, color: "#50fa7b" }}>✓</div><div style={{ fontSize: 48 }}>Review before merge</div><div style={{ fontSize: 25, color: "#aab4d0", marginTop: 20 }}>Deterministic • Static • Source locations included</div></div>}
    <div style={{ position: "absolute", bottom: 45, left: 70, right: 70, height: 5, background: "#202a44" }}><div style={{ height: "100%", width: `${(frame / 360) * 100}%`, background: "#8be9fd" }} /></div>
  </AbsoluteFill>;
}

function Root() { return <Composition id="CapFenceEvaluation" component={App} durationInFrames={360} fps={30} width={1920} height={1080} />; }
registerRoot(Root);
