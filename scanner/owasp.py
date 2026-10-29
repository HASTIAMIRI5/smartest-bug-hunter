const themeToggle = document.getElementById('themeToggle');
const targetInput = document.getElementById('targetInput');
const usernameInput = document.getElementById('usernameInput');
const passwordInput = document.getElementById('passwordInput');
const scanButton = document.getElementById('scanButton');
const authButton = document.getElementById('authButton');
const exportButton = document.getElementById('exportButton');
const exportFormat = document.getElementById('exportFormat');
const findingsList = document.getElementById('findingsList');
const historyList = document.getElementById('historyList');
const categoryChips = document.getElementById('categoryChips');
const riskScore = document.getElementById('riskScore');
const riskLabel = document.getElementById('riskLabel');
const summaryText = document.getElementById('summaryText');

function applyStoredTheme() {
  const storedTheme = localStorage.getItem('theme') || 'dark';
  document.body.dataset.theme = storedTheme;
}

function toggleTheme() {
  const next = document.body.dataset.theme === 'dark' ? 'light' : 'dark';
  document.body.dataset.theme = next;
  localStorage.setItem('theme', next);
}

function renderHistory(items) {
  if (!items || items.length === 0) {
    historyList.innerHTML = '<div class="empty-state">No scan history yet.</div>';
    return;
  }

  historyList.innerHTML = items.map((item) => `
    <article class="history-item">
      <div class="history-meta">
        <div><strong>${item.target}</strong></div>
        <div>${item.created_at}</div>
      </div>
      <div class="finding-top">
        <h3>Risk score: ${item.score}</h3>
        <span class="severity ${item.risk_level.toLowerCase()}">${item.risk_level}</span>
      </div>
      <p>${item.summary}</p>
    </article>
  `).join('');
}

async function loadHistory() {
  try {
    const response = await fetch('/api/history');
    const data = await response.json();
    renderHistory(data.history || []);
  } catch (error) {
    historyList.innerHTML = '<div class="empty-state">History unavailable.</div>';
  }
}

function renderFindings(data) {
  riskScore.textContent = data.score ?? '--';
  riskLabel.textContent = data.risk_level ?? 'Unknown';
  summaryText.textContent = data.summary ?? 'No summary available.';

  categoryChips.innerHTML = '';
  (data.categories || []).forEach((category) => {
    const chip = document.createElement('span');
    chip.className = 'chip';
    chip.textContent = category;
    categoryChips.appendChild(chip);
  });

  if (!data.findings || data.findings.length === 0) {
    findingsList.innerHTML = '<div class="empty-state">No findings found. Great job.</div>';
    return;
  }

  findingsList.innerHTML = data.findings.map((finding) => `
    <article class="finding">
      <div class="finding-top">
        <h3>${finding.title}</h3>
        <span class="severity ${finding.severity.toLowerCase()}">${finding.severity}</span>
      </div>
      <div class="meta">${finding.category}</div>
      <p>${finding.description}</p>
      <p><strong>Evidence:</strong> ${finding.evidence}</p>
      <p><strong>Recommendation:</strong> ${finding.recommendation}</p>
    </article>
  `).join('');
}

async function runScan() {
  const target = (targetInput.value || '').trim();
  if (!target) {
    alert('Please enter a target URL.');
    return;
  }

  scanButton.disabled = true;
  scanButton.textContent = 'Scanning...';
  findingsList.innerHTML = '<div class="empty-state">Scanning target...</div>';

  try {
    const response = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target,
        username: usernameInput.value,
        password: passwordInput.value
      })
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || 'Scan failed');
    }

    renderFindings(data);
    await loadHistory();
  } catch (error) {
    findingsList.innerHTML = `<div class="empty-state">${error.message}</div>`;
  } finally {
    scanButton.disabled = false;
    scanButton.textContent = 'Run Scan';
  }
}

async function runAuthSimulation() {
  const target = (targetInput.value || '').trim();
  if (!target) {
    alert('Please enter a target URL.');
    return;
  }

  authButton.disabled = true;
  authButton.textContent = 'Testing auth...';

  try {
    const response = await fetch('/api/auth-test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target,
        username: usernameInput.value,
        password: passwordInput.value
      })
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || 'Auth simulation failed');
    }

    findingsList.innerHTML = `
      <article class="finding">
        <div class="finding-top">
          <h3>Authentication Simulation</h3>
          <span class="severity ${data.risk_level.toLowerCase() || 'low'}">${data.risk_level}</span>
        </div>
        <div class="meta">A07: Identification and Authentication Failures</div>
        <p>${data.summary}</p>
        <p><strong>Username:</strong> ${data.username}</p>
        <p><strong>Login form found:</strong> ${data.login_form_found ? 'Yes' : 'No'}</p>
        <p><strong>Checks:</strong> ${data.checks.join(' | ')}</p>
      </article>
    `;
    riskScore.textContent = data.risk_level === 'High' ? '75' : data.risk_level === 'Moderate' ? '55' : data.risk_level === 'Low' ? '25' : '0';
    riskLabel.textContent = data.risk_level;
    summaryText.textContent = data.summary;
    categoryChips.innerHTML = '<span class="chip">A07: Identification and Authentication Failures</span>';
  } catch (error) {
    findingsList.innerHTML = `<div class="empty-state">${error.message}</div>`;
  } finally {
    authButton.disabled = false;
    authButton.textContent = 'Run Auth Simulation';
  }
}

function exportHistory() {
  const format = exportFormat.value || 'json';
  window.open(`/api/export?format=${format}`, '_blank');
}

scanButton.addEventListener('click', runScan);
authButton.addEventListener('click', runAuthSimulation);
exportButton.addEventListener('click', exportHistory);
themeToggle.addEventListener('click', toggleTheme);

applyStoredTheme();
loadHistory();

window.addEventListener('keydown', (event) => {
  if (event.key === 'Enter' && document.activeElement === targetInput) {
    runScan();
  }
});
