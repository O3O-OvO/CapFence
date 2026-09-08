import React from "react";
import { AbsoluteFill, Composition, interpolate, spring, useCurrentFrame } from "remotion";
import { registerRoot } from "remotion";

const items = [
  ["network.connect", "dynamic host", "mcp.json:6", "#ff6b6b"],
  ["credential.read", "embedded secret", "mcp.json:7", "#ffb86b"],
  ["filesystem.read", "/home/runner/.ssh", "mcp.json:8", "#bd93f9"],
  ["process.execute", "downloaded script", "mcp.json:4", "#ff79c6"],
] as const;
const clamp = { extrapolateLeft: "clamp" as const, extrapolateRight: "clamp" as const };

function enter(frame: number, delay: number, distance = 50) {
  const p = spring({ frame: frame - delay, fps: 30, config: { damping: 16, stiffness: 100 } });
  return { opacity: p, transform: `translateY(${interpolate(p, [0, 1], [distance, 0])}px) scale(${interpolate(p, [0, 1], [0.94, 1])})` };
}
function Card({ title, children, color = "#8be9fd", style = {} }: { title: string; children: React.ReactNode; color?: string; style?: React.CSSProperties }) {
  return <div style={{ background: "#182235", border: `1px solid ${color}66`, borderRadius: 20, padding: 28, boxShadow: `0 15px 50px ${color}18`, ...style }}><div style={{ color, fontSize: 22, fontWeight: 700, marginBottom: 16 }}>{title}</div>{children}</div>;
}
function Subtitle({ en, zh }: { en: string; zh: string }) {
  return <div style={{ position: "absolute", bottom: 80, left: 70, right: 70, textAlign: "center", fontSize: 24, lineHeight: 1.45, color: "#d8def0", textShadow: "0 2px 8px #000" }}><div>{en}</div><div style={{ color: "#8be9fd", fontSize: 21 }}>{zh}</div></div>;
}
function App() {
  const frame = useCurrentFrame();
  const stage = Math.min(3, Math.floor(frame / 202));
  const stageFrame = frame % 202;
  const pulse = 1 + Math.sin(frame / 7) * 0.04;
  const titles = ["MCP permissions changed", "Safe → dangerous", "A reviewable permission diff", "Block before merge"];
  const subtitles = [
    ["See what an agent can do—and what a pull request adds.", "看清 Agent 能做什么，以及 PR 新增了什么能力。"],
    ["One configuration change can expand the trust boundary.", "一次配置变化，就可能扩大信任边界。"],
    ["Evidence, source locations, and policy reasons—together.", "证据、源码位置和策略原因，一次呈现。"],
    ["Review the permission change before it reaches users.", "在变更进入用户环境前完成审查。"],
  ][stage];
  return <AbsoluteFill style={{ background: "#0b1020", color: "#f8f8f2", fontFamily: "Arial, sans-serif", padding: 70, overflow: "hidden" }}>
    <div style={{ position: "absolute", inset: 0, opacity: 0.18, backgroundImage: "linear-gradient(#8be9fd22 1px, transparent 1px), linear-gradient(90deg, #8be9fd22 1px, transparent 1px)", backgroundSize: "64px 64px", transform: `translate(${(frame % 64) * -0.15}px, ${(frame % 64) * -0.15}px)` }} />
    <div style={{ position: "relative", display: "flex", justifyContent: "space-between", color: "#6272a4", fontSize: 20 }}><b style={{ color: "#8be9fd" }}>CAPFENCE</b><span>STATIC PERMISSION REVIEW / 静态权限审查</span></div>
    <div style={{ position: "relative", marginTop: 60, ...enter(frame, 0) }}><h1 style={{ fontSize: 70, margin: 0, letterSpacing: -3 }}>{titles[stage]}</h1><p style={{ color: "#aab4d0", fontSize: 28, marginTop: 16 }}>{subtitles[0]}</p><p style={{ color: "#8be9fd", fontSize: 24, marginTop: -10 }}>{subtitles[1]}</p></div>
    {stage === 0 && <div style={{ position: "relative", display: "flex", gap: 30, marginTop: 65, alignItems: "center" }}><Card title="SAFE CONFIGURATION / 安全配置" style={enter(stageFrame, 15)}><pre style={{ color: "#50fa7b", fontSize: 24 }}>{`npx server@1.0.0\nGITHUB_TOKEN: "$GITHUB_TOKEN"`}</pre></Card><div style={{ fontSize: 70, color: "#ffb86c", transform: `translateX(${Math.sin(frame / 5) * 10}px)` }}>→</div><Card title="DANGEROUS CHANGE / 危险变更" color="#ff6b6b" style={enter(stageFrame, 28)}><pre style={{ color: "#ff6b6b", fontSize: 24 }}>{`bash -c "curl ... | bash"\nOPENAI_API_KEY: "sk-[redacted]"`}</pre></Card></div>}
    {stage === 1 && <div style={{ position: "relative", display: "grid", gridTemplateColumns: "1fr 1fr", gap: 22, marginTop: 45 }}>{items.map(([kind, scope, loc, color], i) => <Card key={kind} title={`ADDED  ${kind} / 新增能力`} color={color} style={{ ...enter(stageFrame, 8 + i * 9), transform: `${enter(stageFrame, 8 + i * 9).transform} scale(${pulse})` }}><div style={{ fontSize: 30 }}>{scope}</div><div style={{ color: "#aab4d0", fontSize: 20, marginTop: 14 }}>{loc}</div><div style={{ marginTop: 14, height: 4, background: color, width: `${interpolate(stageFrame, [20 + i * 5, 70], [0, 100], clamp)}%`, borderRadius: 4 }} /></Card>)}</div>}
    {stage === 2 && <div style={{ position: "relative", marginTop: 48, display: "flex", gap: 30, alignItems: "center" }}><div style={{ width: 360, height: 330, position: "relative" }}>{items.map(([kind, scope, , color], i) => { const angle = i * Math.PI / 2 + frame / 45; const x = 150 + Math.cos(angle) * 120; const y = 145 + Math.sin(angle) * 120; return <React.Fragment key={kind}><div style={{ position: "absolute", left: x, top: y, width: 18, height: 18, borderRadius: 20, background: color, boxShadow: `0 0 24px ${color}`, transform: `scale(${pulse})` }} /><div style={{ position: "absolute", left: 165, top: 154, width: 120, height: 2, background: `${color}88`, transformOrigin: "left", transform: `rotate(${Math.atan2(y - 154, x - 165)}rad) scaleX(${interpolate(stageFrame, [0, 35], [0, 1], clamp)})` }} /></React.Fragment>; })}<div style={{ position: "absolute", left: 110, top: 110, width: 110, height: 110, borderRadius: 80, background: "#8be9fd22", border: "2px solid #8be9fd", display: "flex", alignItems: "center", justifyContent: "center", textAlign: "center", fontSize: 20 }}>MCP<br/>server</div></div><Card title="CAPFENCE DIFF • POLICY VIOLATIONS / 权限差异 • 策略违规" color="#ffb86c" style={enter(stageFrame, 12)}><div style={{ display: "flex", flexDirection: "column", gap: 20 }}>{["CRITICAL  CF-EXEC-002  downloaded script piped to Bash", "CRITICAL  CF-CRED-002  embedded credential", "HIGH      CF-MCP-001   dynamic remote endpoint"].map((x, i) => <div key={x} style={{ fontFamily: "monospace", fontSize: 23, color: i < 2 ? "#ff6b6b" : "#ffb86c", opacity: interpolate(stageFrame, [15 + i * 10, 28 + i * 10], [0, 1], clamp) }}>{x}</div>)}</div></Card></div>}
    {stage >= 3 && <div style={{ position: "relative", marginTop: 80, textAlign: "center", ...enter(stageFrame, 10) }}><div style={{ fontSize: 120, color: "#50fa7b", transform: `scale(${pulse})` }}>✓</div><div style={{ fontSize: 50 }}>Review before merge / 合并前审查</div><div style={{ fontSize: 25, color: "#aab4d0", marginTop: 20 }}>Deterministic • Static • Source locations included / 确定性 • 静态 • 包含源码位置</div></div>}
    <Subtitle en={subtitles[0]} zh={subtitles[1]} />
    <div style={{ position: "absolute", bottom: 35, left: 70, right: 70, height: 5, background: "#202a44" }}><div style={{ height: "100%", width: `${(frame / 360) * 100}%`, background: "#8be9fd" }} /></div>
  </AbsoluteFill>;
}
function Root() { return <Composition id="CapFenceEvaluation" component={App} durationInFrames={810} fps={30} width={1920} height={1080} />; }
registerRoot(Root);
