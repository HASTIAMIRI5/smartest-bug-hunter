<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Smartest Bug Hunter</title>
    <link rel="stylesheet" href="/static/styles.css" />
  </head>
  <body>
    <div class="container">
      <header>
        <div class="brand">
          <div class="logo">SB</div>
          <h1>Smartest Bug Hunter</h1>
        </div>
        <div class="pill">OWASP detector</div>
      </header>

      <section class="panel form-panel">
        <div class="form-grid">
          <input id="targetInput" type="url" placeholder="https://example.com" />
          <button id="scanButton">Scan target</button>
        </div>
      </section>

      <section id="summary" class="result-grid" aria-live="polite"></section>

      <section class="panel findings-panel">
        <div class="findings-header">
          <h2>Findings</h2>
        </div>
        <div id="findings" class="findings-list"></div>
      </section>
    </div>

    <script>
      const summaryContainer = document.getElementById('summary');
      const findingsContainer = document.getElementById('findings');
      const scanButton = document.getElementById('scanButton');
      const targetInput = document.getElementById('targetInput');

      function renderSummary(data) {
        const total = data?.summary?.total_findings ?? 0;
        const highest = data?.summary?.highest_severity ?? 'info';
        const domain = data?.summary?.domain || 'unknown';

        summaryContainer.innerHTML = `
          <div class="panel metric">
            <span class="metric-label">Target</span>
            <div class="metric-value" style="font-size:1.1rem;">${domain}</div>
          </div>
          <div class="panel metric">
            <span class="metric-label">Total findings</span>
            <div class="metric-value">${total}</div>
          </div>
          <div class="panel metric">
            <span class="metric-label">Highest severity</span>
            <div class="metric-value" style="text-transform: capitalize;">${highest}</div>
          </div>
        `;
      }

      function renderFindings(data) {
        const findings = data?.findings || [];

        if (!findings.length) {
          findingsContainer.innerHTML = `
            <div class="empty-state">
              No findings were detected for this target. Continue testing with additional payloads and authentication flows for a deeper assessment.
            </div>
          `;
          return;
        }

        findingsContainer.innerHTML = findings.map((finding) => `
          <div class="finding-card ${finding.severity}">
            <div class="finding-top">
              <h3>${finding.title}</h3>
              <span class="badge ${finding.severity}">${finding.severity}</span>
            </div>
            <div class="badge" style="margin-bottom:10px; background: rgba(148,163,184,0.08); color: #cbd5e1;">${finding.category}</div>
            <p>${finding.description}</p>
            <p class="finding-meta"><strong>Remediation:</strong> ${finding.remediation}</p>
            ${finding.evidence ? `<p class="finding-meta"><strong>Evidence:</strong> ${finding.evidence}</p>` : ''}
          </div>
        `).join('');
      }

      async function runScan() {
        const target = targetInput.value.trim();
        if (!target) {
          alert('Please enter a target URL.');
          return;
        }

        scanButton.disabled = true;
        scanButton.textContent = 'Scanning...';
        findingsContainer.innerHTML = '<div class="empty-state">Scanning target...</div>';

        try {
          const response = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target_url: target })
          });

          const data = await response.json();
          renderSummary(data);
          renderFindings(data);
        } catch (error) {
          findingsContainer.innerHTML = `
            <div class="empty-state">
              An error occurred while scanning the target. Please confirm the URL and try again.
            </div>
          `;
        } finally {
          scanButton.disabled = false;
          scanButton.textContent = 'Scan target';
        }
      }

      scanButton.addEventListener('click', runScan);
      targetInput.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
          runScan();
        }
      });
    </script>
  </body>
</html>
