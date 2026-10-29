:root {
  --bg: #071922;
  --bg-2: #0c2330;
  --panel: rgba(12, 29, 37, 0.82);
  --panel-alt: rgba(7, 18, 25, 0.82);
  --border: rgba(122, 217, 255, 0.22);
  --text: #edf8ff;
  --muted: #a8d5ee;
  --accent: #2fd3b7;
  --accent-2: #3d7dff;
  --warning: #ffad66;
  --danger: #ff6d6d;
  --success: #7ad79b;
  --shadow: rgba(0, 0, 0, 0.18);
}

body[data-theme="light"] {
  --bg: #eef6fb;
  --bg-2: #dfeef9;
  --panel: rgba(255, 255, 255, 0.9);
  --panel-alt: rgba(237, 247, 252, 0.95);
  --border: rgba(31, 74, 104, 0.15);
  --text: #122331;
  --muted: #49657a;
  --accent: #0aa78d;
  --accent-2: #3d7dff;
  --warning: #bf6c00;
  --danger: #cc2d35;
  --success: #1d8e4a;
  --shadow: rgba(16, 40, 52, 0.12);
}

* { box-sizing: border-box; }

body {
  margin: 0;
  font-family: Inter, "Segoe UI", sans-serif;
  background: linear-gradient(135deg, var(--bg), var(--bg-2));
  color: var(--text);
}

button, input, select {
  font: inherit;
}

.app-shell {
  max-width: 1200px;
  margin: 0 auto;
  padding: 32px 20px 64px;
}

.topbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 16px;
  margin-bottom: 20px;
}

.eyebrow {
  margin: 0 0 8px;
  text-transform: uppercase;
  letter-spacing: 0.14em;
  font-size: 11px;
  color: var(--accent);
}

h1 {
  margin: 0;
  font-size: clamp(2rem, 4vw, 3rem);
}

.dashboard {
  display: grid;
  gap: 22px;
}

.panel {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 18px;
  box-shadow: 0 18px 40px var(--shadow);
  padding: 24px;
}

.scan-row,
.toolbar-row,
.score-wrap,
.section-header,
.finding-top,
.header-actions {
  display: flex;
  gap: 12px;
  align-items: center;
}

.scan-row,
.toolbar-row {
  flex-wrap: wrap;
}

.scan-row.compact {
  margin-top: 12px;
}

input, select {
  flex: 1;
  background: var(--panel-alt);
  border: 1px solid var(--border);
  border-radius: 12px;
  color: var(--text);
  padding: 14px 16px;
  min-width: 120px;
}

button {
  border: none;
  border-radius: 12px;
  background: linear-gradient(135deg, var(--accent), var(--accent-2));
  color: white;
  font-weight: 700;
  padding: 14px 20px;
  cursor: pointer;
}

button:hover { filter: brightness(1.08); }

.secondary-btn {
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid var(--border);
  color: var(--text);
}

#scanButton { min-width: 160px; }

.export-box {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 0 8px;
  color: var(--muted);
}

.export-box select {
  min-width: 110px;
}

.helper-text {
  margin: 14px 0 0;
  color: var(--muted);
}

.score-wrap {
  margin-top: 12px;
}

.score {
  width: 120px;
  height: 120px;
  border-radius: 50%;
  display: grid;
  place-items: center;
  background: radial-gradient(circle at center, rgba(34, 92, 112, 0.9), var(--panel-alt));
  border: 4px solid var(--accent);
  font-size: 2.2rem;
  font-weight: 800;
}

.risk-label {
  margin: 0 0 8px;
  font-size: 1.2rem;
  font-weight: 700;
}

.summary-text {
  margin: 0;
  color: var(--muted);
}

.chips {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.chip {
  display: inline-flex;
  align-items: center;
  background: rgba(80, 144, 255, 0.12);
  border: 1px solid rgba(80, 144, 255, 0.3);
  border-radius: 999px;
  color: var(--text);
  padding: 7px 10px;
  font-size: 0.8rem;
}

.findings-list,
.history-list {
  display: grid;
  gap: 16px;
  margin-top: 20px;
}

.finding,
.history-item {
  background: var(--panel-alt);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 18px;
}

.finding-top {
  justify-content: space-between;
  align-items: center;
  margin-bottom: 10px;
}

.finding h3,
.history-item h3 {
  margin: 0;
  font-size: 1.05rem;
}

.severity {
  padding: 7px 10px;
  border-radius: 999px;
  font-size: 0.74rem;
  font-weight: 700;
  letter-spacing: 0.05em;
  text-transform: uppercase;
}

.severity.critical { background: rgba(255, 109, 109, 0.14); color: var(--danger); border: 1px solid rgba(255, 109, 109, 0.45); }
.severity.high { background: rgba(255, 173, 102, 0.14); color: var(--warning); border: 1px solid rgba(255, 173, 102, 0.45); }
.severity.medium { background: rgba(255, 208, 89, 0.14); color: #dcae1e; border: 1px solid rgba(255, 208, 89, 0.45); }
.severity.low { background: rgba(122, 215, 155, 0.12); color: var(--success); border: 1px solid rgba(122, 215, 155, 0.45); }

.meta {
  color: var(--accent);
  margin: 8px 0;
  font-size: 0.74rem;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.finding p,
.history-item p {
  margin: 8px 0;
  color: var(--text);
  line-height: 1.6;
}

.empty-state {
  color: var(--muted);
  background: rgba(255, 255, 255, 0.02);
  border: 1px dashed var(--border);
  border-radius: 12px;
  padding: 24px 18px;
  text-align: center;
}

.history-item .history-meta {
  display: flex;
  justify-content: space-between;
  gap: 8px;
  flex-wrap: wrap;
  color: var(--muted);
  font-size: 0.8rem;
}

@media (max-width: 700px) {
  .topbar,
  .score-wrap,
  .section-header,
  .finding-top,
  .history-item .history-meta {
    flex-direction: column;
    align-items: flex-start;
  }

  .score {
    width: 100px;
    height: 100px;
  }
}
