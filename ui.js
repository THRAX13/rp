(() => {
'use strict';

/* ───────── utilities ───────── */
const $ = (s, r = document) => r.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmt = (ms) => (ms ? new Date(ms).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—');
const ago = (ms) => {
  if (!ms) return 'never';
  const s = Math.max(0, Math.floor((Date.now() - ms) / 1000));
  if (s < 10) return 'just now';
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.floor(s / 60) + ' min ago';
  if (s < 86400) return Math.floor(s / 3600) + ' hr ago';
  return Math.floor(s / 86400) + ' d ago';
};
const until = (ms) => { const s = Math.max(0, Math.round((ms - Date.now()) / 1000)); return s < 60 ? s + 's' : Math.round(s / 60) + ' min'; };
const INTERVAL_LABEL = { 0: 'Off', 1: 'Every minute', 5: 'Every 5 min', 15: 'Every 15 min', 30: 'Every 30 min', 60: 'Hourly', 360: 'Every 6 hours', 1440: 'Daily' };

let toastTimer;
function toast(msg, bad = false) {
  const el = $('#toast');
  el.textContent = msg;
  el.className = 'toast' + (bad ? ' bad' : '');
  el.style.display = 'block';
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.style.display = 'none'; }, bad ? 5000 : 2800);
}

async function api(path, opts = {}) {
  const method = opts.method || 'GET';
  const o = { method, credentials: 'same-origin', headers: { 'X-Requested-With': 'relayops' } };
  if (method !== 'GET' && method !== 'DELETE') { o.headers['Content-Type'] = 'application/json'; o.body = JSON.stringify(opts.body ?? {}); }
  const r = await fetch('/api' + path, o);
  let data = null;
  try { data = await r.json(); } catch (_) { /* not json */ }
  if (!r.ok) {
    if (r.status === 401 && !path.startsWith('/auth/')) { S.me = null; showAuth(); }
    const e = new Error((data && data.error) || `Request failed (${r.status})`);
    e.status = r.status;
    throw e;
  }
  return data;
}
const guard = (fn) => async (...a) => { try { return await fn(...a); } catch (e) { toast(e.message, true); } };

/* ───────── state ───────── */
const S = {
  me: null, cfg: null, page: 'overview', open: 0,
  overview: null, dests: [], events: { items: [], total: 0 }, filters: { status: '', destination: '', kind: '', q: '', offset: 0 },
  incidents: [], incTab: 'open', settings: null, team: [], audit: [],
};
const PAGES = { overview: 'Overview', destinations: 'Destinations', incidents: 'Incidents', events: 'Event log', settings: 'Settings' };
const ICONS = { overview: '◫', destinations: '◎', incidents: '⚑', events: '≋', settings: '⚙' };

/* ───────── small renderers ───────── */
function pill(kind, text) { return `<span class="pill ${kind}">${esc(text)}</span>`; }
function destPill(d) {
  const m = { healthy: ['ok', 'Healthy'], attention: ['warn', 'Needs attention'], unknown: ['neutral', 'Not checked yet'], paused: ['off', 'Paused'] }[d.status] || ['neutral', d.status];
  return pill(m[0], m[1]);
}
function evPill(e) {
  if (e.status === 'queued') return pill('neutral', e.attempts ? `Retrying (${e.attempts}/${e.max_attempts})` : 'Queued');
  const m = { success: ['ok', 'Delivered'], failed: ['fail', e.dead ? 'Failed · dead-lettered' : 'Failed'], unconfirmed: ['warn', e.dead ? 'Unconfirmed · dead-lettered' : 'Unconfirmed'] }[e.status] || ['neutral', e.status];
  return pill(m[0], m[1]);
}
const dotClass = (st) => (st === 'success' ? 'green' : st === 'failed' ? 'red' : st === 'unconfirmed' ? 'amber' : 'gray');
const respText = (e) => (e.http_status ? `HTTP ${e.http_status}` : e.error ? 'No response' : '—');
const empty = (t, s = '') => `<div class="empty"><b>${esc(t)}</b>${esc(s)}</div>`;

/* ───────── dialogs ───────── */
const dlg = () => $('#dlg');
function openDialog(html, wide = false) {
  const d = dlg();
  d.className = wide ? 'wide' : '';
  d.innerHTML = `<div class="modal">${html}</div>`;
  if (!d.open) d.showModal();
}
function closeDialog() { const d = dlg(); if (d.open) d.close(); }
const modalHead = (t) => `<div class="modalhead"><h3>${esc(t)}</h3><button class="close" data-act="close" aria-label="Close">×</button></div>`;
const codebox = (text, label = 'Copy') => `<div class="codebox pad mono">${esc(text)}<button class="btn small copy" data-act="copy" data-text="${esc(text)}">${label}</button></div>`;

/* ───────── auth ───────── */
async function showAuth(mode) {
  const b = await fetch('/api/bootstrap').then((r) => r.json()).catch(() => ({}));
  const setup = mode === 'setup' || b.setupRequired;
  $('#root').innerHTML = `<div class="authwrap"><div class="authcard">
    <div class="brand"><div class="logo">R</div><div><b>RelayOps</b><small>Delivery Watch</small></div></div>
    ${setup ? `<h1>${b.setupRequired ? 'Set up your workspace' : 'Create a workspace'}</h1><p>${b.setupRequired ? 'Create the first account. You will be the workspace owner.' : 'Create a new workspace and owner account.'}</p>
    <form data-form="setup">
      <div class="field"><label for="f1">YOUR NAME</label><input id="f1" name="name" autocomplete="name" required maxlength="80"></div>
      <div class="field"><label for="f2">AGENCY / WORKSPACE NAME</label><input id="f2" name="workspace" required maxlength="80" placeholder="e.g. Acme Creative Studio"></div>
      <div class="field"><label for="f3">EMAIL</label><input id="f3" name="email" type="email" autocomplete="username" required></div>
      <div class="field"><label for="f4">PASSWORD</label><input id="f4" name="password" type="password" autocomplete="new-password" required minlength="10"><small>At least 10 characters.</small></div>
      <button class="btn primary" type="submit">Create workspace</button></form>
    ${!b.setupRequired ? '<div class="authfoot"><button class="linkbtn" data-act="auth-login">Back to sign in</button></div>' : ''}`
    : `<h1>Sign in</h1><p>Monitor every lead delivery to your clients' systems.</p>
    <form data-form="login">
      <div class="field"><label for="l1">EMAIL</label><input id="l1" name="email" type="email" autocomplete="username" required autofocus></div>
      <div class="field"><label for="l2">PASSWORD</label><input id="l2" name="password" type="password" autocomplete="current-password" required></div>
      <button class="btn primary" type="submit">Sign in</button></form>
    ${b.allowSignup ? '<div class="authfoot">New agency? <button class="linkbtn" data-act="auth-setup">Create a workspace</button></div>' : ''}`}
  </div></div>`;
}

/* ───────── shell ───────── */
function shell() {
  const nav = Object.keys(PAGES).map((p) => `<a href="#/${p}" data-page="${p}" class="${S.page === p ? 'active' : ''}"><span class="ico">${ICONS[p]}</span>${PAGES[p]}${p === 'incidents' && S.open ? `<span class="badge">${S.open}</span>` : ''}</a>`).join('');
  $('#root').innerHTML = `<div class="app"><aside>
    <div class="brand"><div class="logo">R</div><div><b>RelayOps</b><small>Delivery Watch</small></div></div>
    <div><div class="navlabel">WORKSPACE</div><nav class="nav" aria-label="Main">${nav}</nav></div>
    <div class="sidebottom"><strong>${esc(S.me.agency.name)}</strong>${esc(S.me.user.name)} · ${esc(S.me.user.role)}<button class="btn small" data-act="logout">Sign out</button></div>
  </aside><main><header class="top"><div><div class="eyebrow">AGENCY OPERATIONS / DELIVERY RELIABILITY</div><h1>${PAGES[S.page]}</h1></div>
  <div><a class="btn" href="${csvUrl()}" download>↓ Export CSV</a></div></header><div id="view"><div class="loading">Loading…</div></div></main></div>`;
}
function setNav() {
  document.querySelectorAll('.nav a').forEach((a) => a.classList.toggle('active', a.dataset.page === S.page));
  const h = $('.top h1'); if (h) h.textContent = PAGES[S.page];
  const badge = $('.nav a[data-page="incidents"]');
  if (badge) badge.innerHTML = `<span class="ico">${ICONS.incidents}</span>Incidents${S.open ? `<span class="badge">${S.open}</span>` : ''}`;
}

/* ───────── pages ───────── */
function chart(hourly) {
  const max = Math.max(1, ...hourly.map((h) => h.ok + h.bad));
  const H = 100;
  const bars = hourly.map((h, i) => {
    const x = i * 20 + 3;
    const okH = (h.ok / max) * H;
    const badH = (h.bad / max) * H;
    const label = `${new Date(h.t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}: ${h.ok} delivered, ${h.bad} failed`;
    return `<g><title>${esc(label)}</title><rect class="okbar" x="${x}" y="${H + 4 - okH}" width="14" height="${okH}" rx="2"/><rect class="badbar" x="${x}" y="${H + 4 - okH - badH}" width="14" height="${badH}" rx="2"/></g>`;
  }).join('');
  return `<svg class="chart" viewBox="0 0 480 108" preserveAspectRatio="none" role="img" aria-label="Deliveries per hour for the last 24 hours"><line class="grid" x1="0" x2="480" y1="104" y2="104"/>${bars}</svg>
  <div class="chartlegend"><span><i class="green"></i>Delivered</span><span><i class="red"></i>Failed / unconfirmed</span><span>Last 24 hours</span></div>`;
}

function viewOverview() {
  const o = S.overview;
  const st = o.stats;
  const rate = st.success_rate_24h === null ? '—' : Math.round(st.success_rate_24h * 1000) / 10 + '%';
  const welcome = !o.destinations.length ? `<div class="card mb16"><div class="cardtitle"><div><h2>Welcome to RelayOps 👋</h2><p>Get your first delivery path monitored in about two minutes.</p></div><button class="btn primary" data-act="add-dest">+ Add destination</button></div>
    <ol class="muted olist"><li>Add the CRM / webhook URL where your leads should land.</li><li>Copy the unique ingest URL RelayOps gives you into your lead source (ads form, website, Zapier…).</li><li>RelayOps forwards each lead, records the acknowledgement, retries failures and opens incidents when something breaks.</li></ol></div>` : '';
  return `${st.open_incidents ? `<div class="notice bad"><b>${st.open_incidents} open incident${st.open_incidents > 1 ? 's' : ''}.</b> Some destinations are not accepting leads. <a href="#/incidents">Review incidents →</a></div>` : ''}
  ${welcome}
  <div class="grid stats">
    <div class="card"><div class="stathead">Monitored destinations <span>◎</span></div><div class="statnum">${st.destinations}</div><div class="hint">${st.healthy} healthy</div></div>
    <div class="card"><div class="stathead">Delivered (24h) <span class="dot green"></span></div><div class="statnum">${st.delivered_24h}</div><div class="hint">${st.queued ? st.queued + ' queued / retrying' : 'Acknowledged by destinations'}</div></div>
    <div class="card"><div class="stathead">Needs attention (24h) <span class="dot red"></span></div><div class="statnum">${st.failed_24h}</div><div class="hint">Failed or unconfirmed</div></div>
    <div class="card"><div class="stathead">Success rate (24h) <span>↗</span></div><div class="statnum">${rate}</div><div class="hint">${st.latency_avg_ms !== null ? `avg ${st.latency_avg_ms} ms · p95 ${st.latency_p95_ms} ms` : 'No deliveries yet'}</div></div>
  </div>
  <div class="card"><div class="cardtitle"><div><h2>Deliveries per hour</h2><p>Acknowledged vs. failed deliveries</p></div></div>${chart(o.hourly)}</div>
  <div class="grid contentgrid">
    <div class="card"><div class="cardtitle"><div><h2>Destination health</h2><p>Current status of your monitored endpoints</p></div><button class="btn small primary" data-act="add-dest">+ Add destination</button></div>
      ${o.destinations.length ? o.destinations.map((d) => `<div class="health"><div class="healthicon">↗</div><div class="healthbody"><b>${esc(d.name)}</b><span>${esc(d.url)}</span></div>${destPill(d)}</div>`).join('') : empty('No destinations yet', 'Add an endpoint to start monitoring delivery.')}</div>
    <div class="card"><div class="cardtitle"><div><h2>Recent activity</h2><p>Latest delivery events</p></div><a class="btn small" href="#/events">View all</a></div>
      <div class="activity">${o.recent.length ? o.recent.map((e) => `<div class="event" data-act="event" data-id="${esc(e.id)}"><span class="dot eventmark ${dotClass(e.status)}"></span><div class="eventbody"><b>${esc(e.destination_name)} · ${e.kind === 'synthetic' ? 'Check' : 'Lead'}</b><p>${esc(e.error || (e.http_status ? 'HTTP ' + e.http_status : 'Awaiting delivery'))}</p></div><span class="eventtime">${ago(e.created_at)}</span></div>`).join('') : empty('No activity yet', 'Send a test from the Destinations page.')}</div></div>
  </div>`;
}

function viewDestinations() {
  const rows = S.dests.map((d) => {
    const s = d.stats24h; const pct = s.total ? Math.round((s.ok / s.total) * 100) + '%' : '—';
    return `<tr><td><b>${esc(d.name)}</b><div class="sub">${esc(d.url)}</div></td><td>${destPill(d)}${d.last_error && d.status === 'attention' ? `<div class="sub">${esc(d.last_error)}</div>` : ''}</td>
    <td class="mono muted">${esc(d.token_hint)}</td><td>${pct}<div class="sub">${s.total} in 24h</div></td><td>${esc(INTERVAL_LABEL[d.check_interval_min])}</td><td>${ago(d.last_checked_at)}</td>
    <td class="actions"><button class="btn small" data-act="test" data-id="${d.id}">Test now</button> <button class="btn small" data-act="edit-dest" data-id="${d.id}">Details</button> <button class="btn small" data-act="pause" data-id="${d.id}" data-paused="${d.paused ? 1 : 0}">${d.paused ? 'Resume' : 'Pause'}</button> <button class="btn small danger" data-act="del-dest" data-id="${d.id}">Delete</button></td></tr>`;
  }).join('');
  return `<div class="toolbar"><div><h2>Destinations</h2><p>Endpoints that receive your agency's leads. Each has its own private ingest URL.</p></div><button class="btn primary" data-act="add-dest">+ Add destination</button></div>
  <div class="tablewrap"><table><thead><tr><th>Destination</th><th>Status</th><th>Ingest key</th><th>Success (24h)</th><th>Scheduled checks</th><th>Last checked</th><th>Actions</th></tr></thead><tbody>${rows || `<tr><td colspan="7">${empty('No destinations configured', 'Add your first destination to get an ingest URL.')}</td></tr>`}</tbody></table></div>`;
}

function viewIncidents() {
  const list = S.incTab === 'open' ? S.incidents.filter((i) => i.status === 'open') : S.incidents;
  const rows = list.map((i) => `<tr><td><b>INC-${i.number}</b><div class="sub">${esc(i.title)}</div></td><td>${esc(i.destination_name)}<div class="sub">${esc(i.detail || '')}</div></td><td>${pill(i.severity === 'high' ? 'fail' : 'warn', i.severity === 'high' ? 'High' : 'Medium')}</td>
    <td>${fmt(i.opened_at)}<div class="sub">${i.failure_count} failed attempt${i.failure_count === 1 ? '' : 's'}</div></td><td>${i.status === 'open' ? pill('warn', 'Open') : pill('ok', 'Resolved') + `<div class="sub">${fmt(i.resolved_at)} · ${i.resolved_by === 'auto' ? 'auto-resolved' : 'manual'}</div>`}</td>
    <td>${i.status === 'open' ? `<button class="btn small" data-act="resolve" data-id="${i.id}">Resolve</button>` : '—'}</td></tr>`).join('');
  return `<div class="toolbar"><div><h2>Incidents</h2><p>Opened automatically when a destination keeps failing; closed automatically when it recovers.</p></div><a class="btn" href="#/events">Open event log</a></div>
  <div class="tabs"><button data-act="inc-tab" data-tab="open" class="${S.incTab === 'open' ? 'on' : ''}">Open</button><button data-act="inc-tab" data-tab="all" class="${S.incTab === 'all' ? 'on' : ''}">All</button></div>
  <div class="tablewrap"><table><thead><tr><th>Incident</th><th>Destination</th><th>Severity</th><th>Opened</th><th>Status</th><th>Action</th></tr></thead><tbody>${rows || `<tr><td colspan="6">${empty('No incidents', 'All destinations are accepting deliveries. Nice and quiet.')}</td></tr>`}</tbody></table></div>`;
}

function viewEvents() {
  const f = S.filters; const { items, total } = S.events;
  const rows = items.map((e) => `<tr class="click" data-act="event" data-id="${esc(e.id)}"><td><b class="mono">${esc(e.id)}</b><div class="sub">${e.kind === 'synthetic' ? 'Synthetic check' : 'Lead'}${e.idempotency_key ? ' · key ' + esc(e.idempotency_key) : ''}</div></td><td>${esc(e.destination_name)}</td><td>${evPill(e)}${e.status === 'queued' && e.next_attempt_at ? `<div class="sub">next attempt in ${until(e.next_attempt_at)}</div>` : ''}</td><td>${e.attempts}</td><td>${respText(e)}<div class="sub">${esc(e.error || '')}</div></td><td>${e.latency_ms !== null && e.latency_ms !== undefined ? e.latency_ms + ' ms' : '—'}</td><td>${fmt(e.created_at)}</td></tr>`).join('');
  const from = total ? f.offset + 1 : 0; const to = Math.min(total, f.offset + items.length);
  return `<div class="toolbar"><div><h2>Event log</h2><p>Every lead and check, with each delivery attempt recorded.</p></div></div>
  <div class="filters"><input data-filter="q" type="search" placeholder="Search id, error, key…" value="${esc(f.q)}" aria-label="Search">
  <select data-filter="status" aria-label="Status"><option value="">All results</option>${['success', 'failed', 'unconfirmed', 'queued'].map((s) => `<option value="${s}" ${f.status === s ? 'selected' : ''}>${{ success: 'Delivered', failed: 'Failed', unconfirmed: 'Unconfirmed', queued: 'Queued / retrying' }[s]}</option>`).join('')}</select>
  <select data-filter="destination" aria-label="Destination"><option value="">All destinations</option>${S.dests.map((d) => `<option value="${d.id}" ${f.destination === d.id ? 'selected' : ''}>${esc(d.name)}</option>`).join('')}</select>
  <select data-filter="kind" aria-label="Kind"><option value="">Leads + checks</option><option value="lead" ${f.kind === 'lead' ? 'selected' : ''}>Leads only</option><option value="synthetic" ${f.kind === 'synthetic' ? 'selected' : ''}>Checks only</option></select></div>
  <div class="tablewrap"><table><thead><tr><th>Event</th><th>Destination</th><th>Result</th><th>Attempts</th><th>Response</th><th>Latency</th><th>Received</th></tr></thead><tbody>${rows || `<tr><td colspan="7">${empty('No events match', 'Send a lead to an ingest URL or run a test.')}</td></tr>`}</tbody></table></div>
  <div class="pager"><span>${from}–${to} of ${total}</span><span><button class="btn small" data-act="page-prev" ${f.offset ? '' : 'disabled'}>← Newer</button> <button class="btn small" data-act="page-next" ${to < total ? '' : 'disabled'}>Older →</button></span></div>`;
}

function viewSettings() {
  const s = S.settings; const owner = S.me.user.role === 'owner'; const c = S.me.cfg;
  const team = owner ? `<div class="card span2"><div class="cardtitle"><div><h2>Team</h2><p>People who can sign in to this workspace.</p></div></div>
    <div class="tablewrap mb14"><table><thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Last sign-in</th><th></th></tr></thead><tbody>${S.team.map((u) => `<tr><td>${esc(u.name)}</td><td>${esc(u.email)}</td><td>${esc(u.role)}</td><td>${u.last_login_at ? ago(u.last_login_at) : 'never'}</td><td>${u.id === S.me.user.id ? '<span class="muted">you</span>' : `<button class="btn small danger" data-act="del-user" data-id="${u.id}">Remove</button>`}</td></tr>`).join('')}</tbody></table></div>
    <form data-form="team"><div class="formrow"><div class="field"><label>NAME</label><input name="name" required maxlength="80"></div><div class="field"><label>EMAIL</label><input name="email" type="email" required></div></div>
    <div class="formrow"><div class="field"><label>TEMPORARY PASSWORD</label><input name="password" type="password" minlength="10" required autocomplete="new-password"></div><div class="field"><label>ROLE</label><select name="role"><option value="member">Member</option><option value="owner">Owner</option></select></div></div>
    <button class="btn primary" type="submit">Add team member</button></form></div>` : '';
  const audit = owner ? `<div class="card span2"><div class="cardtitle"><div><h2>Audit log</h2><p>The latest 100 security-relevant actions.</p></div></div><div class="tablewrap"><table><thead><tr><th>When</th><th>Who</th><th>Action</th><th>Detail</th><th>IP</th></tr></thead><tbody>${S.audit.map((a) => `<tr><td>${fmt(a.created_at)}</td><td>${esc(a.user_email || 'system')}</td><td class="mono">${esc(a.action)}</td><td>${esc(a.detail || '')}</td><td class="mono muted">${esc(a.ip || '')}</td></tr>`).join('') || `<tr><td colspan="5">${empty('Nothing yet')}</td></tr>`}</tbody></table></div></div>` : '';
  const dev = c.allowPrivateTargets || c.allowHttpTargets;
  return `${dev ? '<div class="notice warn"><b>Developer mode is on.</b> Private-network and/or plain-http targets are allowed. Turn this off before exposing RelayOps to the internet.</div>' : ''}
  <div class="grid settingsgrid">
  <div class="card"><div class="cardtitle"><h2>Workspace</h2></div><form data-form="workspace"><div class="field"><label>WORKSPACE NAME</label><input name="name" value="${esc(s.name)}" required maxlength="80" ${owner ? '' : 'disabled'}></div>${owner ? '<button class="btn primary" type="submit">Save workspace</button>' : '<p class="hint">Only owners can rename the workspace.</p>'}</form></div>
  <div class="card"><div class="cardtitle"><h2>Alerts</h2></div><form data-form="alerts"><div class="field"><label>ALERT WEBHOOK URL</label><input name="alert_webhook_url" type="url" value="${esc(s.alert_webhook_url || '')}" placeholder="https://hooks.slack.com/services/…" ${owner ? '' : 'disabled'}><small>Slack, Discord or any endpoint that accepts JSON. Sent when an incident opens or recovers.</small></div>${owner ? '<button class="btn primary" type="submit">Save</button> <button class="btn" type="button" data-act="test-alert">Send test alert</button>' : ''}</form></div>
  <div class="card"><div class="cardtitle"><h2>Your account</h2></div><form data-form="password"><div class="field"><label>CURRENT PASSWORD</label><input name="current" type="password" autocomplete="current-password" required></div><div class="field"><label>NEW PASSWORD</label><input name="next" type="password" autocomplete="new-password" minlength="10" required></div><button class="btn primary" type="submit">Change password</button></form></div>
  <div class="card"><div class="cardtitle"><h2>System</h2></div><div class="grid">
    <div class="settingitem"><b>Version</b><span>${esc(c.version)}</span></div>
    <div class="settingitem"><b>Public URL</b><span>${esc(c.publicUrl)}</span></div>
    <div class="settingitem"><b>Delivery policy</b><span>Up to ${c.maxAttempts} attempts with exponential backoff, then dead-letter + incident</span></div>
    <div class="settingitem"><b>Data retention</b><span>Events ${s.retention_days} days · lead payloads removed after delivery, or ${s.payload_retention_days} days if undelivered</span></div></div></div>
  ${team}${audit}</div>`;
}

function csvUrl() {
  const f = S.filters; const p = new URLSearchParams();
  ['status', 'destination', 'kind', 'q'].forEach((k) => f[k] && p.set(k, f[k]));
  return '/api/events.csv' + (p.toString() ? '?' + p : '');
}

/* ───────── loading ───────── */
async function load(page, quiet) {
  const view = $('#view');
  if (!view) return;
  try {
    if (page === 'overview') S.overview = await api('/overview');
    if (page === 'destinations' || page === 'events') S.dests = (await api('/destinations')).items;
    if (page === 'events') {
      const f = S.filters; const p = new URLSearchParams({ limit: 50, offset: f.offset });
      ['status', 'destination', 'kind', 'q'].forEach((k) => f[k] && p.set(k, f[k]));
      S.events = await api('/events?' + p);
    }
    if (page === 'incidents') S.incidents = (await api('/incidents')).items;
    if (page === 'settings') {
      S.settings = await api('/settings');
      if (S.me.user.role === 'owner') { S.team = (await api('/team')).items; S.audit = (await api('/audit')).items; }
    }
    if (page !== 'incidents') api('/incidents?status=open').then((r) => { S.open = r.items.length; setNav(); }).catch(() => {});
    else S.open = S.incidents.filter((i) => i.status === 'open').length;
    if (S.page !== page) return;
    view.innerHTML = { overview: viewOverview, destinations: viewDestinations, incidents: viewIncidents, events: viewEvents, settings: viewSettings }[page]();
    setNav();
  } catch (e) {
    if (!quiet && S.me) view.innerHTML = `<div class="notice bad">${esc(e.message)}</div>`;
  }
}

function route() {
  const p = (location.hash.replace(/^#\//, '') || 'overview').split('?')[0];
  S.page = PAGES[p] ? p : 'overview';
  if (!S.me) return;
  if (!$('#view')) shell();
  setNav();
  $('#view').innerHTML = '<div class="loading">Loading…</div>';
  load(S.page);
}

/* ───────── destination dialogs ───────── */
function destForm(d) {
  const iv = S.me.cfg.intervals;
  return `<form data-form="dest" data-id="${d ? d.id : ''}">
    <div class="field"><label for="d1">NAME</label><input id="d1" name="name" required maxlength="80" value="${esc(d?.name)}" placeholder="e.g. Client CRM webhook"></div>
    <div class="field"><label for="d2">ENDPOINT URL</label><input id="d2" name="url" type="url" required value="${esc(d?.url)}" placeholder="https://example.com/webhook"><small>Leads are POSTed here. ${S.me.cfg.allowHttpTargets ? 'http:// allowed in developer mode.' : 'HTTPS only.'}</small></div>
    <div class="field"><label for="d3">CHECK URL (OPTIONAL)</label><input id="d3" name="check_url" type="url" value="${esc(d?.check_url || '')}" placeholder="Same as endpoint URL if empty"><small>Scheduled checks send a harmless test event (header <code>X-RelayOps-Synthetic: true</code>). Point this at a test/health endpoint if your CRM would create a lead from it.</small></div>
    <div class="formrow"><div class="field"><label for="d4">SCHEDULED CHECKS</label><select id="d4" name="check_interval_min">${iv.map((m) => `<option value="${m}" ${(d?.check_interval_min || 0) === m ? 'selected' : ''}>${INTERVAL_LABEL[m]}</option>`).join('')}</select></div>
    <div class="field"><label for="d5">SIGN FORWARDED REQUESTS (OPTIONAL)</label><input id="d5" name="outbound_secret" type="password" autocomplete="off" minlength="16" placeholder="${d?.has_outbound_secret ? '•••• set — type to replace' : 'Shared secret, 16+ chars'}"><small>Adds <code>X-RelayOps-Signature</code> (HMAC-SHA256) so your endpoint can verify the sender.</small></div></div>
    ${d?.has_outbound_secret ? '<label class="check"><input type="checkbox" name="clear_outbound"> Remove the outbound signing secret</label>' : ''}
    <label class="check"><input type="checkbox" name="require_signature" ${d?.require_signature ? 'checked' : ''}><span>Require signed requests on the ingest URL<br><span class="hint">Reject leads that don't carry a valid <code>X-RelayOps-Signature</code>. Recommended for production.</span></span></label>
    <div class="modalfoot"><button class="btn" type="button" data-act="close">Cancel</button><button class="btn primary" type="submit">${d ? 'Save changes' : 'Create destination'}</button></div></form>`;
}

function curlSnippet(url, secret) {
  return `# Send a lead
curl -X POST '${url}' \\
  -H 'Content-Type: application/json' \\
  -H 'Idempotency-Key: lead-12345' \\
  -d '{"name":"Test Lead","email":"lead@example.com"}'

# Same, with signature (recommended)
TS=$(date +%s); BODY='{"name":"Test Lead","email":"lead@example.com"}'
SIG=$(printf '%s.%s' "$TS" "$BODY" | openssl dgst -sha256 -hmac '${secret}' | sed 's/^.* //')
curl -X POST '${url}' -H 'Content-Type: application/json' \\
  -H "X-RelayOps-Signature: t=$TS,v1=$SIG" -d "$BODY"`;
}

function revealDialog(title, { ingest_url, signing_secret }) {
  openDialog(`${modalHead(title)}
  <div class="notice warn"><b>Copy these now.</b> For security they are stored hashed/encrypted and cannot be shown again. You can rotate them any time.</div>
  ${ingest_url ? `<div class="label">INGEST URL — point your lead source at this</div>${codebox(ingest_url)}` : ''}
  ${signing_secret ? `<div class="label">SIGNING SECRET — used to sign requests (HMAC-SHA256)</div>${codebox(signing_secret)}` : ''}
  ${ingest_url && signing_secret ? `<div class="label">TRY IT</div>${codebox(curlSnippet(ingest_url, signing_secret), 'Copy')}` : ''}
  <div class="modalfoot"><button class="btn primary" data-act="close">I've saved them</button></div>`, true);
}

/* ───────── event detail ───────── */
async function showEvent(id) {
  const { event: e, attempts } = await api('/events/' + encodeURIComponent(id));
  const canRetry = (e.status === 'failed' || e.status === 'unconfirmed') && e.has_payload;
  openDialog(`${modalHead('Delivery ' + e.id)}
  <dl class="kv"><dt>Result</dt><dd>${evPill(e)}</dd><dt>Destination</dt><dd>${esc(e.destination_name)}</dd><dt>Kind</dt><dd>${e.kind === 'synthetic' ? 'Synthetic check' : 'Lead'}</dd>
  <dt>Received</dt><dd>${fmt(e.created_at)}${e.source_ip ? ' from ' + esc(e.source_ip) : ''}</dd><dt>Completed</dt><dd>${fmt(e.completed_at)}</dd>
  <dt>Payload</dt><dd>${e.payload_bytes} bytes${e.has_payload ? '' : ' (content removed)'}<br><span class="mono muted">sha256 ${esc(e.payload_sha256 || '')}</span></dd>
  ${e.idempotency_key ? `<dt>Idempotency key</dt><dd>${esc(e.idempotency_key)}</dd>` : ''}</dl>
  <div class="label">ATTEMPTS (${attempts.length}/${e.max_attempts})</div>
  <div class="timeline">${attempts.map((a) => `<div class="attempt"><span class="n">${a.n}</span><div>${evPill({ status: a.result, attempts: 0 })} <span class="muted">${a.http_status ? 'HTTP ' + a.http_status : ''}</span>${a.error ? `<small>${esc(a.error)}</small>` : ''}${a.response_snippet ? `<small class="mono">${esc(a.response_snippet.slice(0, 160))}</small>` : ''}</div><small>${a.latency_ms ?? '—'} ms<br>${fmt(a.created_at)}</small></div>`).join('') || '<p class="muted">No attempts yet.</p>'}</div>
  ${e.status === 'queued' && e.next_attempt_at ? `<div class="notice">Next attempt in ${until(e.next_attempt_at)}.</div>` : ''}
  <div class="modalfoot">${canRetry ? `<button class="btn primary" data-act="retry" data-id="${esc(e.id)}">Retry delivery</button>` : ''}<button class="btn" data-act="close">Close</button></div>`, true);
}

/* ───────── actions ───────── */
const actions = {
  close: closeDialog,
  copy: guard(async (el) => { await navigator.clipboard.writeText(el.dataset.text); toast('Copied'); }),
  'auth-setup': () => showAuth('setup'),
  'auth-login': () => showAuth('login'),
  logout: guard(async () => { await api('/auth/logout', { method: 'POST' }); S.me = null; showAuth(); }),
  'add-dest': () => openDialog(`${modalHead('Add destination')}${destForm(null)}`),
  'edit-dest': guard(async (el) => {
    const d = (await api('/destinations/' + el.dataset.id)).destination;
    openDialog(`${modalHead('Destination details')}${destForm(d)}
    <hr class="rule">
    <div class="label">INGEST URL</div><p class="muted tight">Key <code>${esc(d.token_hint)}</code> — the full URL is only shown when created or rotated.</p>
    <div class="modalfoot start"><button class="btn" data-act="rotate-token" data-id="${d.id}">Rotate ingest URL</button><button class="btn" data-act="rotate-secret" data-id="${d.id}">Rotate signing secret</button></div>`, true);
  }),
  'rotate-token': guard(async (el) => {
    if (!confirm('Rotate the ingest URL? The old URL stops working immediately — update your lead source with the new one.')) return;
    const r = await api(`/destinations/${el.dataset.id}/rotate-token`, { method: 'POST' });
    revealDialog('New ingest URL', { ingest_url: r.ingest_url }); load(S.page, true);
  }),
  'rotate-secret': guard(async (el) => {
    if (!confirm('Rotate the signing secret? Senders using the old secret will be rejected if signatures are required.')) return;
    const r = await api(`/destinations/${el.dataset.id}/rotate-secret`, { method: 'POST' });
    revealDialog('New signing secret', { signing_secret: r.signing_secret });
  }),
  'del-dest': guard(async (el) => {
    if (!confirm('Delete this destination and its event history? Its ingest URL stops working.')) return;
    await api('/destinations/' + el.dataset.id, { method: 'DELETE' }); toast('Destination deleted'); load(S.page, true);
  }),
  pause: guard(async (el) => {
    const paused = el.dataset.paused !== '1';
    await api('/destinations/' + el.dataset.id, { method: 'PATCH', body: { paused } });
    toast(paused ? 'Paused — new leads are rejected until resumed' : 'Resumed'); load(S.page, true);
  }),
  test: guard(async (el) => {
    el.disabled = true; el.textContent = 'Testing…';
    try {
      const { delivery: d } = await api(`/destinations/${el.dataset.id}/test`, { method: 'POST' });
      if (d.status === 'success') toast(`✓ Acknowledged — HTTP ${d.http_status} in ${d.latency_ms} ms`);
      else toast(`✗ ${d.error || 'Delivery failed'}`, true);
    } finally { load(S.page, true); }
  }),
  event: guard((el) => showEvent(el.dataset.id)),
  retry: guard(async (el) => { await api(`/events/${el.dataset.id}/retry`, { method: 'POST' }); closeDialog(); toast('Re-queued for delivery'); setTimeout(() => load(S.page, true), 1200); }),
  resolve: guard(async (el) => { await api(`/incidents/${el.dataset.id}/resolve`, { method: 'POST' }); toast('Incident resolved'); load('incidents', true); }),
  'inc-tab': (el) => { S.incTab = el.dataset.tab; $('#view').innerHTML = viewIncidents(); },
  'page-prev': () => { S.filters.offset = Math.max(0, S.filters.offset - 50); load('events'); },
  'page-next': () => { S.filters.offset += 50; load('events'); },
  'test-alert': guard(async () => { const r = await api('/settings/test-alert', { method: 'POST' }); r.ok ? toast('✓ Test alert delivered') : toast('Alert failed: ' + (r.error || 'unknown error'), true); }),
  'del-user': guard(async (el) => { if (!confirm('Remove this person from the workspace?')) return; await api('/team/' + el.dataset.id, { method: 'DELETE' }); toast('Removed'); load('settings', true); }),
};

const forms = {
  login: guard(async (f) => { await api('/auth/login', { method: 'POST', body: formData(f) }); await boot(); }),
  setup: guard(async (f) => { await api('/auth/setup', { method: 'POST', body: formData(f) }); await boot(); }),
  dest: guard(async (f) => {
    const v = formData(f); const id = f.dataset.id;
    const body = { name: v.name, url: v.url, check_url: v.check_url || null, check_interval_min: Number(v.check_interval_min), require_signature: !!v.require_signature };
    if (v.clear_outbound) body.outbound_secret = null; else if (v.outbound_secret) body.outbound_secret = v.outbound_secret;
    if (id) { await api('/destinations/' + id, { method: 'PATCH', body }); closeDialog(); toast('Destination updated'); }
    else { const r = await api('/destinations', { method: 'POST', body }); revealDialog('Destination created', r); }
    load(S.page, true);
  }),
  workspace: guard(async (f) => { await api('/settings', { method: 'PATCH', body: { name: formData(f).name } }); S.me.agency.name = formData(f).name; toast('Workspace saved'); shell(); setNav(); load('settings'); }),
  alerts: guard(async (f) => { await api('/settings', { method: 'PATCH', body: { alert_webhook_url: formData(f).alert_webhook_url || null } }); toast('Alert settings saved'); }),
  password: guard(async (f) => { await api('/auth/password', { method: 'POST', body: formData(f) }); f.reset(); toast('Password changed'); }),
  team: guard(async (f) => { await api('/team', { method: 'POST', body: formData(f) }); f.reset(); toast('Team member added'); load('settings', true); }),
};
function formData(f) {
  const o = {};
  new FormData(f).forEach((v, k) => { o[k] = typeof v === 'string' ? v.trim() : v; });
  f.querySelectorAll('input[type=checkbox]').forEach((c) => { o[c.name] = c.checked; });
  return o;
}

/* ───────── events wiring ───────── */
document.addEventListener('click', (ev) => {
  const el = ev.target.closest('[data-act]');
  if (el && actions[el.dataset.act]) { ev.preventDefault(); actions[el.dataset.act](el, ev); }
});
document.addEventListener('submit', (ev) => {
  const f = ev.target.closest('form[data-form]');
  if (f && forms[f.dataset.form]) { ev.preventDefault(); forms[f.dataset.form](f); }
});
let qTimer;
document.addEventListener('input', (ev) => {
  const el = ev.target.closest('[data-filter="q"]');
  if (!el) return;
  clearTimeout(qTimer);
  qTimer = setTimeout(() => { S.filters.q = el.value.trim(); S.filters.offset = 0; load('events').then(() => { const i = $('[data-filter="q"]'); if (i) { i.focus(); i.setSelectionRange(i.value.length, i.value.length); } }); }, 350);
});
document.addEventListener('change', (ev) => {
  const el = ev.target.closest('[data-filter]');
  if (!el || el.dataset.filter === 'q') return;
  S.filters[el.dataset.filter] = el.value; S.filters.offset = 0; load('events');
});
dlg().addEventListener('click', (ev) => { if (ev.target === dlg()) closeDialog(); });
window.addEventListener('hashchange', route);
setInterval(() => {
  if (!S.me || document.hidden || dlg().open) return;
  const a = document.activeElement;
  if (a && /^(INPUT|SELECT|TEXTAREA)$/.test(a.tagName) && $('#view')?.contains(a)) return;
  load(S.page, true);
}, 8000);

/* ───────── boot ───────── */
async function boot() {
  try {
    const s = await api('/session');
    S.me = { user: s.user, agency: s.agency, cfg: s.config };
    closeDialog();
    if (!location.hash) location.hash = '#/overview';
    $('#root').innerHTML = '';
    route();
  } catch (e) {
    if (e.status === 401) showAuth();
    else $('#root').innerHTML = `<div class="authwrap"><div class="authcard"><h1>Can't reach RelayOps</h1><p>${esc(e.message)}</p></div></div>`;
  }
}
boot();
})();
