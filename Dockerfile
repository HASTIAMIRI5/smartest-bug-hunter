* {
  box-sizing: border-box;
}

body {
  margin: 0;
  font-family: Inter, "Segoe UI", sans-serif;
  background: linear-gradient(135deg, #081522 0%, #12263b 40%, #0d1e2d 100%);
  color: #edf4ff;
}

img {
  max-width: 100%;
}

a {
  color: #80d7ff;
  text-decoration: none;
}

button, input {
  font: inherit;
}

.auth-shell {
  min-height: 100vh;
  display: grid;
  place-items: center;
  padding: 24px;
}

.auth-card {
  width: min(100%, 480px);
  background: rgba(7, 18, 29, 0.88);
  border: 1px solid rgba(148, 163, 184, 0.2);
  border-radius: 18px;
  padding: 28px;
  box-shadow: 0 30px 55px rgba(5, 10, 17, 0.4);
}

.brand-row {
  display: flex;
  align-items: center;
  gap: 14px;
  margin-bottom: 22px;
}

.logo {
  width: 52px;
  height: 52px;
  border-radius: 14px;
  display: grid;
  place-items: center;
  background: linear-gradient(135deg, #14b8a6, #60a5fa);
  color: #031925;
  font-weight: 900;
  font-size: 1.2rem;
}

.brand-row h1,
.topbar h1,
.panel h3,
.sidebar h2 {
  margin: 0;
}

.brand-row p,
.eyebrow,
.muted {
  margin: 4px 0 0;
  color: #90a9be;
}

label {
  display: block;
  margin-top: 18px;
  margin-bottom: 8px;
  font-weight: 600;
}

input {
  width: 100%;
  border-radius: 12px;
  border: 1px solid rgba(148, 163, 184, 0.25);
  background: rgba(15, 29, 39, 0.9);
  color: white;
  padding: 12px 14px;
}

.primary-btn,
.secondary-btn,
button {
  border: none;
  border-radius: 12px;
  padding: 12px 18px;
  font-weight: 700;
  cursor: pointer;
  transition: 0.2s ease;
}

.primary-btn,
button {
  background: linear-gradient(135deg, #22c55e, #14b8a6);
  color: #031925;
}

.secondary-btn {
  background: rgba(148, 163, 184, 0.12);
  color: #edf4ff;
  border: 1px solid rgba(148, 163, 184, 0.15);
}

.primary-btn:hover,
.secondary-btn:hover,
button:hover {
  filter: brightness(1.05);
}

.alert {
  padding: 12px 14px;
  border-radius: 10px;
  margin-bottom: 18px;
  font-size: 0.95rem;
}

.alert-error {
  background: rgba(239, 68, 68, 0.12);
  border: 1px solid rgba(239, 68, 68, 0.35);
  color: #fecaca;
}

.auth-link-row {
  margin-top: 18px;
  color: #abc0d6;
  display: flex;
  justify-content: center;
  gap: 8px;
}

.page-shell {
  display: grid;
  grid-template-columns: 260px 1fr;
  min-height: 100vh;
}

.sidebar {
  padding: 28px 18px;
  background: rgba(7, 18, 29, 0.82);
  border-right: 1px solid rgba(148, 163, 184, 0.15);
}

nav {
  display: flex;
  flex-direction: column;
  gap: 12px;
  margin-top: 28px;
}

nav a {
  padding: 12px 14px;
  border-radius: 10px;
  color: #cfe5f6;
  background: rgba(15, 29, 39, 0.7);
  border: 1px solid rgba(148, 163, 184, 0.18);
}

nav a.nav-active {
  background: rgba(20, 184, 166, 0.14);
  border-color: rgba(20, 184, 166, 0.3);
}

.content {
  padding: 28px;
}

.topbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 18px;
  margin-bottom: 20px;
}

.eyebrow {
  font-size: 0.8rem;
  letter-spacing: 0.12em;
  text-transform: uppercase;
}

.scanner-box {
  display: flex;
  gap: 12px;
  min-width: min(100%, 450px);
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(180px, 1fr));
  gap: 16px;
  margin-bottom: 20px;
}

.stat-card,
.panel {
  background: rgba(10, 24, 35, 0.9);
  border: 1px solid rgba(148, 163, 184, 0.18);
  border-radius: 16px;
  padding: 20px;
  box-shadow: 0 18px 40px rgba(5, 10, 17, 0.22);
}

.stat-card span {
  display: block;
  color: #98afc4;
  margin-bottom: 8px;
}

.stat-card strong {
  font-size: 2rem;
}

.content-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}

.breakdown-list,
.scan-list,
.admin-list {
  list-style: none;
  padding: 0;
  margin: 0;
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.breakdown-list li,
.scan-list li,
.admin-list li {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
  padding: 12px 0;
  border-bottom: 1px solid rgba(148, 163, 184, 0.14);
}

.scan-meta {
  display: flex;
  gap: 12px;
  color: #9ab1c6;
  font-size: 0.84rem;
}

.detail-topbar {
  margin-bottom: 24px;
}

.detail-actions {
  display: flex;
  gap: 12px;
}

.findings-panel {
  margin-top: 22px;
}

.finding-card {
  background: rgba(15, 29, 39, 0.82);
  border: 1px solid rgba(148, 163, 184, 0.18);
  border-left: 4px solid #94a3b8;
  border-radius: 14px;
  padding: 16px;
  margin-top: 12px;
}

.severity-critical {
  border-left-color: #ef4444;
}

.severity-high {
  border-left-color: #f97316;
}

.severity-medium {
  border-left-color: #facc15;
}

.severity-low {
  border-left-color: #60a5fa;
}

.severity-info {
  border-left-color: #94a3b8;
}

.finding-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 12px;
}

.finding-header h4 {
  margin: 0;
}

.severity-pill {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 5px 10px;
  border-radius: 999px;
  font-size: 0.7rem;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.severity-pill.severity-critical { background: rgba(239, 68, 68, 0.17); color: #fecaca; }
.severity-pill.severity-high { background: rgba(249, 115, 22, 0.15); color: #fdba74; }
.severity-pill.severity-medium { background: rgba(250, 204, 21, 0.16); color: #fde68a; }
.severity-pill.severity-low { background: rgba(96, 165, 250, 0.15); color: #bfdbfe; }
.severity-pill.severity-info { background: rgba(148, 163, 184, 0.14); color: #dbeafe; }

.finding-card p,
.finding-detail {
  color: #dfeaf6;
  line-height: 1.6;
}

@media (max-width: 900px) {
  .page-shell {
    grid-template-columns: 1fr;
  }

  .sidebar {
    border-right: none;
    border-bottom: 1px solid rgba(148, 163, 184, 0.15);
  }

  .content-grid,
  .stats-grid {
    grid-template-columns: 1fr;
  }

  .topbar {
    flex-direction: column;
    align-items: flex-start;
  }

  .scanner-box {
    width: 100%;
    flex-direction: column;
  }
}
