async function runScan() {
  const targetInput = document.getElementById('targetInput');
  const button = document.getElementById('scanButton');
  const findingsList = document.getElementById('findingsList');
  const riskScore = document.getElementById('riskScore');
  const riskLabel = document.getElementById('riskLabel');
  const summaryText = document.getElementById('summaryText');
  const categoryChips = document.getElementById('categoryChips');

  const target = (targetInput.value || '').trim();
  if (!target) {
    alert('Please enter a target URL.');
    return;
  }

  button.disabled = true;
  button.textContent = 'Scanning...';
  findingsList.innerHTML = '<div class="empty-state">Scanning target...</div>';

  try {
    const response = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || 'Scan failed');
    }

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
  } catch (error) {
    findingsList.innerHTML = `<div class="empty-state">${error.message}</div>`;
    riskScore.textContent = '--';
    riskLabel.textContent = 'Error';
    summaryText.textContent = 'The scan could not complete.';
  } finally {
    button.disabled = false;
    button.textContent = 'Run Scan';
  }
}

document.getElementById('scanButton').addEventListener('click', runScan);

document.getElementById('targetInput').addEventListener('keydown', (event) => {
  if (event.key === 'Enter') {
    runScan();
  }
});
