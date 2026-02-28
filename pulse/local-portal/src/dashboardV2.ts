/**
 * Unified Dashboard HTML (v2 redesign).
 *
 * 3 tabs: Activity (operational dashboard), Scoped Access (rich grants), Security.
 * Activity tab is the main screen: wallet balance, watchdog status strip,
 * blocked-command alerts, active grants with revoke, recent transactions.
 */

export function getDashboardHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Agent Watchdog</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap');

    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg: #0D0D0D;
      --bg-card: #141414;
      --bg-hover: #1A1A1A;
      --border: #2A2A2A;
      --border-mid: #708090;
      --text: #E0E0E0;
      --text-dim: #708090;
      --accent: #4FD1C5;
      --accent-dim: rgba(79, 209, 197, 0.15);
      --red: #E53E3E;
      --red-dim: rgba(229, 62, 62, 0.12);
      --yellow: #D69E2E;
      --yellow-dim: rgba(214, 158, 46, 0.12);
      --green: #39FF14;
      --green-dim: rgba(57, 255, 20, 0.12);
      --mono: 'IBM Plex Mono', monospace;
      --sans: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    body {
      font-family: var(--sans);
      font-size: 14px;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      min-height: 100vh;
    }

    /* ---- Layout ---- */
    .shell { max-width: 1100px; margin: 0 auto; padding: 28px 24px; }

    /* ---- Header ---- */
    .header-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--border-mid);
      margin-bottom: 0;
    }
    .header-bar h1 {
      font-size: 17px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }
    .header-right {
      display: flex;
      align-items: baseline;
      gap: 16px;
    }
    .header-balance {
      font-family: var(--mono);
      font-size: 22px;
      font-weight: 700;
      color: var(--accent);
    }
    .header-addr {
      font-family: var(--mono);
      font-size: 12px;
      color: var(--text-dim);
    }

    /* ---- Watchdog status strip ---- */
    .wd-strip {
      display: flex;
      align-items: center;
      gap: 18px;
      padding: 8px 0;
      font-size: 12px;
      font-family: var(--mono);
      color: var(--text-dim);
      border-bottom: 1px solid var(--border);
      margin-bottom: 20px;
    }
    .wd-strip .dot {
      display: inline-block;
      width: 7px; height: 7px;
      border-radius: 50%;
      margin-right: 5px;
      vertical-align: middle;
    }
    .dot-green { background: var(--green); }
    .dot-red   { background: var(--red); }
    .dot-amber { background: var(--yellow); }
    .dot-gray  { background: var(--text-dim); }
    .wd-strip .sep { color: var(--border); }

    /* ---- Tabs ---- */
    .tab-bar {
      display: flex;
      gap: 0;
      border-bottom: 1px solid var(--border);
      margin-bottom: 22px;
    }
    .tab-bar button {
      background: none;
      border: none;
      border-bottom: 2px solid transparent;
      padding: 10px 22px;
      font-family: var(--sans);
      font-size: 13px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--text-dim);
      cursor: pointer;
      transition: all 0.15s;
    }
    .tab-bar button:hover { color: var(--text); }
    .tab-bar button.active {
      color: var(--accent);
      border-bottom-color: var(--accent);
    }
    .tab-bar .alert-count {
      display: inline-block;
      min-width: 18px; height: 18px; line-height: 18px;
      padding: 0 5px;
      margin-left: 6px;
      border-radius: 9px;
      background: var(--red);
      color: #fff;
      font-size: 11px;
      font-weight: 600;
      text-align: center;
    }
    .tab-panel { display: none; }
    .tab-panel.active { display: block; }

    /* ---- Section headers ---- */
    .section-label {
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.07em;
      color: var(--text-dim);
      margin: 22px 0 10px 0;
    }
    .section-label:first-child { margin-top: 0; }

    /* ---- Alert cards ---- */
    .alert-card {
      background: var(--red-dim);
      border: 1px solid var(--red);
      border-left: 3px solid var(--red);
      padding: 14px 18px;
      margin-bottom: 8px;
      display: flex;
      align-items: flex-start;
      gap: 12px;
    }
    .alert-icon {
      font-family: var(--mono);
      font-size: 14px;
      font-weight: 700;
      color: var(--red);
      flex-shrink: 0;
      margin-top: 1px;
    }
    .alert-body { flex: 1; min-width: 0; }
    .alert-title { font-weight: 600; font-size: 13px; }
    .alert-detail {
      font-size: 12px;
      color: var(--text-dim);
      font-family: var(--mono);
      margin-top: 2px;
    }
    .alert-meta {
      display: flex;
      align-items: center;
      gap: 10px;
      flex-shrink: 0;
    }
    .alert-time {
      font-size: 11px;
      color: var(--text-dim);
      font-family: var(--mono);
      white-space: nowrap;
    }

    /* ---- Buttons ---- */
    .btn {
      font-family: var(--sans);
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      padding: 6px 14px;
      border: 1px solid var(--border-mid);
      background: var(--bg);
      color: var(--text);
      cursor: pointer;
      transition: all 0.15s;
    }
    .btn:hover { border-color: var(--accent); color: var(--accent); }
    .btn-accent {
      background: var(--accent);
      color: var(--bg);
      border-color: var(--accent);
    }
    .btn-accent:hover { background: #3dbdb2; border-color: #3dbdb2; color: var(--bg); }
    .btn-red { border-color: var(--red); color: var(--red); }
    .btn-red:hover { background: var(--red-dim); }
    .btn-sm { padding: 4px 10px; font-size: 11px; }

    /* ---- Grant cards (Activity compact) ---- */
    .grant-compact {
      background: var(--bg-card);
      border: 1px solid var(--border);
      padding: 14px 18px;
      margin-bottom: 8px;
      transition: border-color 0.15s;
    }
    .grant-compact:hover { border-color: #3A3A3A; }
    .grant-compact-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 6px;
    }
    .grant-compact-domain {
      font-family: var(--mono);
      font-size: 13px;
      font-weight: 500;
      color: var(--text);
    }
    .grant-compact-meta {
      display: flex;
      align-items: center;
      gap: 20px;
      font-size: 12px;
      color: var(--text-dim);
      font-family: var(--mono);
    }
    .grant-compact-actions {
      display: flex;
      gap: 8px;
      margin-top: 10px;
    }
    .budget-bar {
      height: 4px;
      background: var(--border);
      margin-top: 8px;
      position: relative;
    }
    .budget-bar-fill {
      height: 100%;
      background: var(--accent);
      transition: width 0.3s;
    }
    .budget-bar-fill.warn { background: var(--yellow); }
    .budget-bar-fill.danger { background: var(--red); }

    /* ---- Tables ---- */
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th {
      text-align: left;
      font-weight: 600;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-dim);
      padding: 8px 10px;
      border-bottom: 1px solid var(--border);
    }
    td {
      padding: 9px 10px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }
    tr:hover td { background: var(--bg-hover); }
    .mono { font-family: var(--mono); color: var(--accent); }
    .mono-dim { font-family: var(--mono); color: var(--text-dim); }

    /* ---- Badges ---- */
    .badge {
      display: inline-block;
      padding: 2px 8px;
      font-size: 11px;
      font-weight: 600;
      font-family: var(--mono);
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }
    .badge-active  { color: var(--green);    border: 1px solid var(--green); }
    .badge-expired { color: var(--text-dim); border: 1px solid var(--text-dim); }
    .badge-revoked { color: var(--red);      border: 1px solid var(--red); }
    .badge-paid    { color: var(--accent);   border: 1px solid var(--accent); }
    .badge-denied  { color: var(--red);      border: 1px solid var(--red); }

    /* ---- Rich grant cards (Scoped Access tab) ---- */
    .grant-rich {
      background: var(--bg-card);
      border: 1px solid var(--border);
      padding: 20px;
      margin-bottom: 12px;
    }
    .grant-rich-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 10px;
    }
    .grant-rich-id {
      font-family: var(--mono);
      font-size: 12px;
      color: var(--accent);
    }
    .grant-rich-summary {
      font-size: 14px;
      font-weight: 600;
      padding: 10px 14px;
      background: var(--accent-dim);
      border-left: 3px solid var(--accent);
      margin: 8px 0 10px 0;
    }
    .grant-rich-description {
      font-size: 12px;
      color: var(--text-dim);
      line-height: 1.5;
      white-space: pre-wrap;
      margin-bottom: 12px;
    }
    .api-card {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 8px 12px;
      border: 1px solid var(--border);
      margin-bottom: 4px;
      font-size: 12px;
    }
    .api-method {
      font-family: var(--mono);
      font-size: 11px;
      font-weight: 600;
      padding: 2px 6px;
      background: var(--border-mid);
      color: var(--bg);
      text-align: center;
      min-width: 42px;
    }
    .api-path { font-family: var(--mono); color: var(--text); flex: 1; }
    .api-domain { font-family: var(--mono); color: var(--accent); font-size: 11px; }
    .api-desc { font-size: 11px; color: var(--text-dim); }
    .grant-rich-budget {
      display: flex;
      gap: 24px;
      margin: 12px 0 8px 0;
      font-family: var(--mono);
      font-size: 13px;
    }
    .grant-rich-budget .label {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-dim);
      font-family: var(--sans);
      display: block;
      margin-bottom: 2px;
    }
    .grant-rich-ttl {
      font-family: var(--mono);
      font-size: 12px;
      color: var(--text-dim);
      margin-top: 6px;
    }
    .grant-rich-actions {
      display: flex;
      gap: 8px;
      margin-top: 14px;
      padding-top: 12px;
      border-top: 1px solid var(--border);
    }

    /* ---- Security (PID / stats) ---- */
    .stat-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 10px;
      margin-bottom: 22px;
    }
    .stat-box {
      background: var(--bg-card);
      border: 1px solid var(--border);
      padding: 14px;
      text-align: center;
    }
    .stat-box .sv {
      font-family: var(--mono);
      font-size: 26px;
      font-weight: 700;
    }
    .stat-box .sl {
      font-size: 10px;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--text-dim);
      margin-top: 4px;
    }
    .pid-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      padding: 14px 18px;
      margin-bottom: 8px;
    }
    .pid-header {
      display: flex; align-items: center; justify-content: space-between;
      margin-bottom: 6px;
    }
    .pid-name { font-weight: 600; font-size: 14px; }
    .pid-tree {
      font-family: var(--mono);
      font-size: 12px;
      color: var(--text-dim);
      padding-left: 14px;
    }
    .pid-tree div { padding: 1px 0; }

    /* ---- Modal ---- */
    .modal-overlay {
      display: none;
      position: fixed; inset: 0;
      background: rgba(0,0,0,0.7);
      z-index: 1000;
      align-items: center;
      justify-content: center;
    }
    .modal-overlay.open { display: flex; }
    .modal {
      background: var(--bg-card);
      border: 1px solid var(--border);
      padding: 28px;
      width: 480px;
      max-width: 95vw;
      max-height: 90vh;
      overflow-y: auto;
    }
    .modal h2 {
      font-size: 15px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      margin-bottom: 18px;
    }
    .fg { margin-bottom: 14px; }
    .fg label {
      display: block;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-dim);
      margin-bottom: 5px;
    }
    .fg input, .fg select {
      width: 100%;
      padding: 7px 10px;
      background: var(--bg);
      border: 1px solid var(--border);
      color: var(--text);
      font-family: var(--mono);
      font-size: 13px;
    }
    .fg input:focus, .fg select:focus {
      outline: none;
      border-color: var(--accent);
    }
    .modal-actions {
      display: flex;
      gap: 10px;
      justify-content: flex-end;
      margin-top: 20px;
    }

    .empty {
      text-align: center;
      padding: 32px 20px;
      color: var(--text-dim);
      font-size: 13px;
    }

    /* ---- Clickable table rows ---- */
    .clickable-row { cursor: pointer; }
    .clickable-row:hover td { background: rgba(79, 209, 197, 0.04); }

  </style>
</head>
<body>
<div class="shell">

  <!-- ============================================================ -->
  <!-- HEADER                                                       -->
  <!-- ============================================================ -->
  <div class="header-bar">
    <h1>Agent Watchdog</h1>
    <div class="header-right">
      <span class="header-balance" id="h-balance">--</span>
      <span class="header-addr" id="h-addr"></span>
    </div>
  </div>

  <!-- ============================================================ -->
  <!-- WATCHDOG STATUS STRIP                                        -->
  <!-- ============================================================ -->
  <div class="wd-strip" id="wd-strip">
    <span><span class="dot dot-gray" id="wd-dot"></span><span id="wd-label">Watchdog</span></span>
  </div>

  <!-- ============================================================ -->
  <!-- TABS                                                         -->
  <!-- ============================================================ -->
  <div class="tab-bar">
    <button class="active" data-tab="activity">Activity<span class="alert-count" id="alert-count" style="display:none">0</span></button>
    <button data-tab="access">Grants</button>
    <button data-tab="security">Security</button>
  </div>

  <!-- ============================================================ -->
  <!-- TAB: Activity                                                -->
  <!-- ============================================================ -->
  <div id="tab-activity" class="tab-panel active">
    <div id="alerts-section"></div>

    <div class="section-label" id="grants-label" style="display:none">Active Grants</div>
    <div id="active-grants"></div>

    <div class="section-label">Recent Transactions</div>
    <table>
      <thead><tr><th>Time</th><th>Domain</th><th>Amount</th><th>Status</th><th>TX</th></tr></thead>
      <tbody id="tx-body"></tbody>
    </table>
    <div id="tx-empty" class="empty" style="display:none">No transactions yet.</div>
  </div>

  <!-- ============================================================ -->
  <!-- TAB: Grants                                                  -->
  <!-- ============================================================ -->
  <div id="tab-access" class="tab-panel">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
      <div class="section-label" style="margin:0">Active Grants</div>
      <button class="btn btn-sm" onclick="openGrantModal()">New Grant</button>
    </div>
    <div id="sa-active"></div>

    <div class="section-label" style="margin-top:28px">Past Grants</div>
    <div id="sa-past"></div>
  </div>

  <!-- ============================================================ -->
  <!-- TAB: Security                                                -->
  <!-- ============================================================ -->
  <div id="tab-security" class="tab-panel">
    <div class="stat-grid" id="sec-stats"></div>
    <div class="section-label">Monitored Processes</div>
    <div id="pid-sets"></div>
    <div style="margin-top:10px;display:flex;gap:8px">
      <button class="btn btn-sm" onclick="detectCursor()">Auto-detect Cursor</button>
      <button class="btn btn-sm" onclick="openPidModal()">Register PID</button>
    </div>
    <div class="section-label" style="margin-top:26px">Blocked Commands Log</div>
    <table>
      <thead><tr><th>Time</th><th>PID</th><th>Command</th><th>Source</th><th>Detail</th></tr></thead>
      <tbody id="blocked-log"></tbody>
    </table>
  </div>
</div>

<!-- Grant modal -->
<div class="modal-overlay" id="grant-modal">
  <div class="modal">
    <h2>Grant Scoped Access</h2>
    <div class="fg"><label>Domain(s) (comma-separated)</label><input id="gm-domains" placeholder="api.example.com"></div>
    <div class="fg"><label>Max Total Budget (USDC)</label><input type="number" id="gm-budget" value="1" step="0.01" min="0"></div>
    <div class="fg"><label>Max Per Transaction (USDC)</label><input type="number" id="gm-pertx" value="0.5" step="0.01" min="0"></div>
    <div class="fg"><label>Duration (minutes)</label><input type="number" id="gm-ttl" value="10" min="1"></div>
    <div class="fg"><label>Summary (optional)</label><input id="gm-summary" placeholder="Purpose of this grant"></div>
    <div class="modal-actions">
      <button class="btn" onclick="closeGrantModal()">Cancel</button>
      <button class="btn btn-accent" onclick="submitGrant()">Approve</button>
    </div>
  </div>
</div>

<!-- PID modal -->
<div class="modal-overlay" id="pid-modal">
  <div class="modal">
    <h2>Register PID</h2>
    <div class="fg"><label>Name</label><select id="pm-name"><option value="cursor">cursor</option><option value="pulse">pulse</option></select></div>
    <div class="fg"><label>PID</label><input type="number" id="pm-pid" placeholder="12345" min="1"></div>
    <div class="modal-actions">
      <button class="btn" onclick="closePidModal()">Cancel</button>
      <button class="btn btn-accent" onclick="submitPid()">Register</button>
    </div>
  </div>
</div>

<script>
/* ================================================================
   Helpers
   ================================================================ */
var currentTab = 'activity';

function timeAgo(ts) {
  var d = Math.floor((Date.now() - ts) / 1000);
  if (d < 5) return 'just now';
  if (d < 60) return d + 's ago';
  if (d < 3600) return Math.floor(d/60) + 'm ago';
  if (d < 86400) return Math.floor(d/3600) + 'h ago';
  return new Date(ts).toLocaleDateString();
}
function shortAddr(a) { return (!a || a.length < 12) ? (a||'--') : a.slice(0,6)+'...'+a.slice(-4); }
function fmtUsdc(atomic) {
  var n = Number(atomic) / 1e6;
  if (n === 0) return '0';
  if (n < 0.01) return n.toFixed(6).replace(/0+$/,'').replace(/\\.$/,'');
  return n.toFixed(4).replace(/0+$/,'').replace(/\\.$/,'');
}
function esc(s) { var d=document.createElement('div'); d.textContent=s||''; return d.innerHTML; }
function explorerUrl(txHash, network) {
  if (!txHash) return null;
  var chainId = (network||'').split(':')[1];
  var byChainId = {'8453':'https://basescan.org/tx/','84532':'https://sepolia.basescan.org/tx/','1':'https://etherscan.io/tx/','11155111':'https://sepolia.etherscan.io/tx/'};
  var byName = {'base':'https://basescan.org/tx/','base-sepolia':'https://sepolia.basescan.org/tx/','base-mainnet':'https://basescan.org/tx/','ethereum':'https://etherscan.io/tx/','sepolia':'https://sepolia.etherscan.io/tx/'};
  var base = byChainId[chainId] || byName[network] || byName[String(network||'').toLowerCase()] || 'https://sepolia.basescan.org/tx/';
  return base + txHash;
}
function pct(spent, total) { if (!total) return 0; return Math.min(100, Math.round((spent/total)*100)); }

/* ================================================================
   Tabs
   ================================================================ */
document.querySelectorAll('.tab-bar button').forEach(function(b) {
  b.addEventListener('click', function() {
    currentTab = b.getAttribute('data-tab');
    document.querySelectorAll('.tab-panel').forEach(function(p){p.classList.remove('active');});
    document.querySelectorAll('.tab-bar button').forEach(function(x){x.classList.remove('active');});
    document.getElementById('tab-'+currentTab).classList.add('active');
    b.classList.add('active');
    refresh();
  });
});

/* ================================================================
   Header: wallet balance
   ================================================================ */
function loadWallet() {
  fetch('/api/wallet').then(function(r){return r.json();}).then(function(w) {
    if (w.authenticated === false) {
      document.getElementById('h-balance').textContent = '--';
      document.getElementById('h-addr').textContent = 'wallet not authenticated';
      return;
    }
    if (w.address) {
      var usdc = w.balances ? w.balances.USDC : null;
      document.getElementById('h-balance').textContent = usdc != null ? '$'+usdc+' USDC' : '--';
      document.getElementById('h-addr').textContent = shortAddr(w.address);
    } else {
      document.getElementById('h-balance').textContent = '--';
      document.getElementById('h-addr').textContent = 'wallet not connected';
    }
  }).catch(function() {
    document.getElementById('h-balance').textContent = '--';
  });
}

/* ================================================================
   Watchdog status strip
   ================================================================ */
function loadWdStrip() {
  Promise.all([
    fetch('/api/watchdog/stats').then(function(r){return r.json();}),
    fetch('/api/watchdog/pid-sets').then(function(r){return r.json();})
  ]).then(function(arr) {
    var stats = arr[0], pids = arr[1];
    var dot = document.getElementById('wd-dot');
    var label = document.getElementById('wd-label');
    var parts = [];

    var names = Object.keys(pids);
    if (names.length === 0) {
      dot.className = 'dot dot-amber';
      parts.push('No processes registered');
    } else {
      dot.className = 'dot dot-green';
      names.forEach(function(n) {
        var e = pids[n];
        var childCount = e.children ? e.children.length : 0;
        if (n === 'cursor') {
          parts.push('Monitoring ' + esc(n) + ' (PID ' + e.rootPid + ')' + (childCount ? ' + ' + childCount + ' children' : ''));
        }
      });
    }

    var sep = ' <span class="sep">|</span> ';
    if (stats.commands_blocked > 0) parts.push(stats.commands_blocked + ' blocked');
    if (stats.files_observed > 0) parts.push(stats.files_observed + ' files observed');

    label.innerHTML = parts.join(sep) || 'Watchdog idle';
  }).catch(function() {
    document.getElementById('wd-dot').className = 'dot dot-gray';
    document.getElementById('wd-label').textContent = 'Watchdog offline';
  });
}

/* ================================================================
   Activity: Alerts (blocked commands)
   ================================================================ */
function loadAlerts() {
  fetch('/api/watchdog/events?type=command_blocked&limit=20').then(function(r){return r.json();}).then(function(evts) {
    var active = (evts||[]).filter(function(e){ return !e.dismissed; });
    var el = document.getElementById('alerts-section');
    var badge = document.getElementById('alert-count');
    if (active.length === 0) {
      el.innerHTML = '';
      badge.style.display = 'none';
      return;
    }
    badge.textContent = active.length;
    badge.style.display = '';

    var h = '';
    active.forEach(function(ev) {
      h += '<div class="alert-card">'
        + '<div class="alert-icon">X</div>'
        + '<div class="alert-body">'
        + '<div class="alert-title">BLOCKED: ' + esc(ev.source_pid_set) + ' (PID ' + ev.pid + ') attempted <span class="mono">' + esc(ev.command + ' ' + (ev.args||[]).join(' ')) + '</span></div>'
        + '<div class="alert-detail">' + esc(ev.detail) + '</div>'
        + '</div>'
        + '<div class="alert-meta">'
        + '<span class="alert-time">' + timeAgo(ev.timestamp) + '</span>'
        + '<button class="btn btn-accent btn-sm" onclick="grantFromBlocked(\\'' + esc(ev.id) + '\\',\\'' + esc((ev.args||[]).join(' ')) + '\\')">Grant Access</button>'
        + '<button class="btn btn-sm" onclick="dismissAlert(\\'' + ev.id + '\\')">Dismiss</button>'
        + '</div></div>';
    });
    el.innerHTML = h;
  }).catch(function(){});
}

function grantFromBlocked(id, argsStr) {
  var domain = '';
  var m = argsStr.match(/https?:\\/\\/([^/\\s]+)/);
  if (m) domain = m[1];
  document.getElementById('gm-domains').value = domain;
  document.getElementById('gm-budget').value = '1';
  document.getElementById('gm-pertx').value = '0.5';
  document.getElementById('gm-ttl').value = '10';
  document.getElementById('gm-summary').value = 'Granted from blocked command';
  openGrantModal();
}

function dismissAlert(id) {
  fetch('/api/watchdog/events/'+id+'/dismiss',{method:'POST'}).then(function(){loadAlerts();});
}

/* ================================================================
   Activity: Active grants (compact)
   ================================================================ */
function loadActiveGrants() {
  fetch('/api/scoped-access?active_only=true').then(function(r){return r.json();}).then(function(grants) {
    var now = Date.now();
    var active = (grants||[]).filter(function(g){ return !g.revoked_at && g.expires_at > now; });
    var el = document.getElementById('active-grants');
    var label = document.getElementById('grants-label');

    if (active.length === 0) {
      el.innerHTML = '<div class="empty" style="padding:16px">No active grants. Grants appear here when you approve agent payment access.</div>';
      label.style.display = 'none';
      return;
    }
    label.style.display = '';

    var h = '';
    active.forEach(function(g) {
      var domains = parseDomains(g.allowed_domains);
      var spent = Number(g.total_spent_atomic)||0;
      var total = Number(g.max_total_spend)||0;
      var p = pct(spent, total);
      var barClass = p > 80 ? 'danger' : (p > 50 ? 'warn' : '');
      var remaining = Math.max(0, Math.floor((g.expires_at - now)/1000));
      var rm = Math.floor(remaining/60), rs = remaining%60;

      // Count transactions for this grant
      h += '<div class="grant-compact">'
        + '<div class="grant-compact-header">'
        + '<span class="grant-compact-domain">' + domains.map(esc).join(', ') + '</span>'
        + '<span class="badge badge-active">ACTIVE</span>'
        + '</div>'
        + '<div class="grant-compact-meta">'
        + '<span>$' + fmtUsdc(spent) + ' / $' + fmtUsdc(total) + ' USDC</span>'
        + '<span>' + rm + 'm ' + rs + 's remaining</span>'
        + '</div>'
        + '<div class="budget-bar"><div class="budget-bar-fill ' + barClass + '" style="width:' + p + '%"></div></div>'
        + '<div class="grant-compact-actions">'
        + '<a href="/delegation/' + g.session_id + '" class="btn btn-sm" style="text-decoration:none">Details</a>'
        + '<button class="btn btn-red btn-sm" onclick="revokeGrant(\\'' + g.session_id + '\\')">Revoke</button>'
        + '</div></div>';
    });
    el.innerHTML = h;
  }).catch(function(){});
}

function parseDomains(raw) {
  if (Array.isArray(raw)) return raw;
  try { var p = JSON.parse(raw||'[]'); return Array.isArray(p)?p:[]; } catch(e) { return []; }
}

function revokeGrant(sid) {
  if (!confirm('Revoke this grant?')) return;
  fetch('/api/scoped-access/'+sid+'/revoke',{method:'POST',headers:{'Content-Type':'application/json'}}).then(function(){refresh();});
}

/* ================================================================
   Activity: Recent transactions
   ================================================================ */
function loadRecentTx() {
  fetch('/api/transactions').then(function(r){return r.json();}).then(function(txs) {
    var body = document.getElementById('tx-body');
    var empty = document.getElementById('tx-empty');
    if (!Array.isArray(txs)||txs.length===0) { body.innerHTML=''; empty.style.display=''; return; }
    empty.style.display='none';

    var h = '';
    txs.slice(0,15).forEach(function(tx) {
      var ok = tx.decision === 'ALLOW' || tx.decision === 'APPROVED';
      var time = timeAgo(tx.created_at);
      var txLink = tx.tx_hash
        ? '<a href="'+explorerUrl(tx.tx_hash, tx.network)+'" target="_blank" class="mono" style="font-size:11px">'+shortAddr(tx.tx_hash)+'</a>'
        : '<span class="mono-dim">--</span>';
      h += '<tr>'
        + '<td class="mono-dim">'+time+'</td>'
        + '<td class="mono">'+esc(tx.domain)+'</td>'
        + '<td class="mono">$'+fmtUsdc(tx.amount)+'</td>'
        + '<td><span class="badge '+(ok?'badge-paid':'badge-denied')+'">'+(ok?'PAID':(tx.deny_code||'DENIED'))+'</span></td>'
        + '<td>'+txLink+'</td></tr>';
    });
    body.innerHTML = h;
  }).catch(function(){});
}

/* ================================================================
   Scoped Access tab: rich grant cards
   ================================================================ */
function loadScopedAccess() {
  fetch('/api/scoped-access').then(function(r){return r.json();}).then(function(grants) {
    var now = Date.now();
    var active = [], past = [];
    (grants||[]).forEach(function(g) {
      if (!g.revoked_at && g.expires_at > now) active.push(g);
      else past.push(g);
    });

    document.getElementById('sa-active').innerHTML = active.length
      ? renderGrantsTable(active, true)
      : '<div class="empty" style="padding:14px">No active grants.</div>';
    document.getElementById('sa-past').innerHTML = past.length
      ? renderGrantsTable(past, false)
      : '<div class="empty" style="padding:14px">No past grants.</div>';
  }).catch(function(e){console.error('loadScopedAccess',e);});
}

function renderGrantsTable(items, isActive) {
  var now = Date.now();
  var h = '<table><thead><tr>'
    + '<th>ID</th><th>Summary</th><th>APIs</th><th>Budget (USDC)</th>'
    + (isActive ? '<th>TTL</th>' : '<th>Status</th>')
    + '<th>Created</th>'
    + '<th>Actions</th></tr></thead><tbody>';

  items.forEach(function(g) {
    var domains = parseDomains(g.allowed_domains);
    var apis = parseApis(g.allowed_apis);
    var spent = Number(g.total_spent_atomic)||0;
    var total = Number(g.max_total_spend)||0;

    var apisShort;
    if (apis.length > 0) {
      apisShort = apis.length === 1
        ? esc(apis[0].method+' '+apis[0].path)
        : apis.length + ' APIs';
    } else {
      apisShort = domains.map(esc).join(', ') || '--';
    }

    h += '<tr class="clickable-row" onclick="window.location.href=\\'/delegation/' + g.session_id + '\\';">'
      + '<td><span class="mono">' + g.session_id.slice(0,8) + '...</span></td>'
      + '<td>' + esc(g.summary || '--') + '</td>'
      + '<td><span class="mono-dim">' + apisShort + '</span></td>'
      + '<td><span class="mono">' + fmtUsdc(spent) + ' / ' + fmtUsdc(total) + '</span></td>';

    if (isActive) {
      var remaining = Math.max(0, Math.floor((g.expires_at - now)/1000));
      var rm = Math.floor(remaining/60), rs = remaining%60;
      h += '<td><span class="mono">' + rm + 'm ' + rs + 's</span></td>';
    } else {
      var status = g.revoked_at ? 'revoked' : 'expired';
      h += '<td><span class="badge badge-' + status + '">' + status.toUpperCase() + '</span></td>';
    }

    var createdTs = g.created_at || (g.expires_at - (g.ttl_seconds||0)*1000);
    h += '<td><span class="mono-dim">' + timeAgo(createdTs) + '</span></td>';

    h += '<td onclick="event.stopPropagation()">';
    if (isActive) {
      h += '<button class="btn btn-red btn-sm" onclick="event.stopPropagation();revokeGrant(\\'' + g.session_id + '\\')">Revoke</button>';
    }
    h += '</td></tr>';
  });

  h += '</tbody></table>';
  return h;
}

function parseApis(raw) {
  if (Array.isArray(raw)) return raw;
  try { var p = JSON.parse(raw||'[]'); return Array.isArray(p)?p:[]; } catch(e) { return []; }
}

/* ================================================================
   Security tab
   ================================================================ */
function loadSecurity() {
  Promise.all([
    fetch('/api/watchdog/stats').then(function(r){return r.json();}),
    fetch('/api/watchdog/pid-sets').then(function(r){return r.json();}),
    fetch('/api/watchdog/events?type=command_blocked&limit=50').then(function(r){return r.json();})
  ]).then(function(arr) {
    var stats=arr[0], pids=arr[1], blocked=arr[2];

    document.getElementById('sec-stats').innerHTML =
      '<div class="stat-box"><div class="sv" style="color:var(--red)">'+(stats.commands_blocked||0)+'</div><div class="sl">Blocked</div></div>'
      +'<div class="stat-box"><div class="sv">'+(stats.commands_allowed||0)+'</div><div class="sl">Allowed</div></div>'
      +'<div class="stat-box"><div class="sv">'+(stats.files_observed||0)+'</div><div class="sl">Files Observed</div></div>'
      +'<div class="stat-box"><div class="sv">'+(stats.pid_sets_registered||0)+'</div><div class="sl">PID Sets</div></div>';

    var ph = '';
    Object.keys(pids).forEach(function(name) {
      var e = pids[name];
      var sc = name==='pulse'?'badge-active':'badge-revoked';
      var st = name==='pulse'?'WHITELISTED':'MONITORED';
      ph += '<div class="pid-card"><div class="pid-header">'
        +'<span class="pid-name">'+esc(name)+' <span class="mono-dim">(PID '+e.rootPid+')</span></span>'
        +'<span class="badge '+sc+'">'+st+'</span></div>';
      if (e.children && e.children.length > 0) {
        ph += '<div class="pid-tree">';
        e.children.slice(0,20).forEach(function(c){ph+='<div>|- '+esc(c.comm)+' (PID '+c.pid+')</div>';});
        if (e.children.length>20) ph+='<div>... and '+(e.children.length-20)+' more</div>';
        ph += '</div>';
      }
      ph += '</div>';
    });
    document.getElementById('pid-sets').innerHTML = ph || '<div class="empty" style="padding:14px">No PID sets registered.</div>';

    var lh = '';
    (blocked||[]).forEach(function(ev) {
      lh += '<tr><td class="mono-dim">'+new Date(ev.timestamp).toLocaleTimeString()+'</td>'
        +'<td class="mono">'+ev.pid+'</td>'
        +'<td class="mono">'+esc(ev.command+' '+(ev.args||[]).join(' '))+'</td>'
        +'<td>'+esc(ev.source_pid_set)+'</td>'
        +'<td class="mono-dim" style="font-size:11px">'+esc(ev.detail)+'</td></tr>';
    });
    document.getElementById('blocked-log').innerHTML = lh;
  }).catch(function(e){console.error('loadSecurity',e);});
}

function detectCursor() {
  fetch('/api/watchdog/auto-detect-cursor',{method:'POST'}).then(function(r){return r.json();}).then(function(d){
    if (d.detected) alert('Detected Cursor PID: '+d.rootPid);
    else alert('Cursor process not found. Is Cursor running?');
    refresh();
  }).catch(function(e){alert('Error: '+e.message);});
}

/* ================================================================
   Modals
   ================================================================ */
function openGrantModal()  { document.getElementById('grant-modal').classList.add('open'); }
function closeGrantModal() { document.getElementById('grant-modal').classList.remove('open'); }
function openPidModal()    { document.getElementById('pid-modal').classList.add('open'); }
function closePidModal()   { document.getElementById('pid-modal').classList.remove('open'); }

function submitGrant() {
  var domains = document.getElementById('gm-domains').value.split(',').map(function(d){return d.trim();}).filter(Boolean);
  var budget = parseFloat(document.getElementById('gm-budget').value)||1;
  var perTx = parseFloat(document.getElementById('gm-pertx').value)||0.5;
  var ttl = parseInt(document.getElementById('gm-ttl').value)||10;
  var summary = document.getElementById('gm-summary').value;
  if (!domains.length) { alert('At least one domain is required.'); return; }

  fetch('/request-scoped-access',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({agent_id:'cursor',policy:{
      allowed_domains:domains,
      max_total_spend:Math.round(budget*1e6),
      max_per_tx:Math.round(perTx*1e6),
      ttl_seconds:ttl*60,
      summary:summary||'Dashboard grant'
    }})
  }).then(function(r){return r.json();}).then(function(data){
    if (data.request_id) {
      return fetch('/approval/'+data.request_id+'/demo-approve').then(function(){
        closeGrantModal(); refresh();
      });
    } else if (data.status==='approved') {
      closeGrantModal(); refresh();
    } else {
      alert('Unexpected: '+JSON.stringify(data));
    }
  }).catch(function(e){alert('Error: '+e.message);});
}

function submitPid() {
  var name = document.getElementById('pm-name').value;
  var pid = parseInt(document.getElementById('pm-pid').value);
  if (!pid||pid<1) { alert('Valid PID required.'); return; }
  fetch('/api/watchdog/register-pid',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({name:name,pid:pid})
  }).then(function(){closePidModal();refresh();}).catch(function(e){alert('Error: '+e.message);});
}

/* ================================================================
   Refresh
   ================================================================ */
function refresh() {
  loadWallet();
  loadWdStrip();
  if (currentTab==='activity') { loadAlerts(); loadActiveGrants(); loadRecentTx(); }
  else if (currentTab==='access') { loadScopedAccess(); }
  else if (currentTab==='security') { loadSecurity(); }
}

refresh();
setInterval(refresh, 4000);
</script>
</body>
</html>`;
}
