// Lightweight CSS helpers for the HTML renderer.
// Keep it self-contained to avoid external assets.
pub const BASE_STYLE: &str = r#"
:root {
  --bg: #05050c;
  --panel: #0f1121;
  --accent: #ff5c8a;
  --accent-2: #8ef1b8;
  --muted: #a3a3b3;
  --text: #f4f6ff;
  --mono: 'JetBrains Mono', 'Fira Code', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  --sans: 'Inter', 'Space Grotesk', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
}
* { box-sizing: border-box; }
body {
  background: radial-gradient(120% 120% at 20% 20%, rgba(255,92,138,0.08), transparent),
              radial-gradient(120% 120% at 80% 0%, rgba(142,241,184,0.08), transparent),
              var(--bg);
  color: var(--text);
  font-family: var(--sans);
  padding: 28px;
  line-height: 1.55;
}
section.log { max-width: 900px; margin: 0 auto; }
.card {
  background: var(--panel);
  border: 1px solid rgba(255,92,138,0.25);
  border-radius: 14px;
  padding: 16px 18px;
  margin: 12px 0;
  box-shadow: 0 10px 35px rgba(0,0,0,0.35);
}
.card h3 { margin: 0 0 8px; letter-spacing: 0.04em; font-size: 14px; text-transform: uppercase; color: var(--muted); }
.say { color: var(--accent-2); font-weight: 600; margin: 6px 0; }
.ask { color: #ffd166; font-weight: 700; margin: 6px 0; }
.oracle { color: var(--accent-2); font-weight: 700; margin: 6px 0; }
.fetch, .ui, .log { color: var(--muted); font-size: 14px; margin: 4px 0; }
.button { display: inline-block; margin: 6px 6px 6px 0; padding: 8px 14px; border-radius: 999px; border: 1px solid var(--accent); color: var(--accent); background: transparent; font-weight: 600; letter-spacing: 0.02em; }
.text { margin: 6px 0; }
.error { color: var(--accent); font-weight: 700; margin: 10px 0; }
code, pre { font-family: var(--mono); }
pre.snippet { background: #0b0d18; padding: 12px; border-radius: 10px; border: 1px solid rgba(255,92,138,0.35); overflow-x: auto; }
"#;
