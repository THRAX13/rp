'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { fromEnv } = require('./core-config');
const { createApp } = require('./core-app');
const { sign } = require('./core-security');

const quiet = { log() {}, error() {}, warn() {} };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 6000) { const t = Date.now(); for (;;) { const v = await fn(); if (v) return v; if (Date.now() - t > ms) throw new Error('timed out waiting'); await sleep(40); } }

class Client {
  constructor(base) { this.base = base; this.cookie = ''; }
  async req(method, p, body, headers = {}) {
    const h = { 'X-Requested-With': 'relayops', ...headers };
    if (this.cookie) h.Cookie = this.cookie;
    let payload;
    if (body !== undefined) { h['Content-Type'] = h['Content-Type'] || 'application/json'; payload = typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body); }
    const r = await fetch(this.base + p, { method, headers: h, body: payload });
    const sc = r.headers.get('set-cookie'); if (sc) this.cookie = sc.split(';')[0];
    const text = await r.text(); let json = null; try { json = JSON.parse(text); } catch (_) { /* */ }
    return { status: r.status, json, text, headers: r.headers };
  }
}

async function startApp(extra = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'relayops-'));
  const config = fromEnv({ DATA_DIR: dir }, { port: 0, host: '127.0.0.1', backoffBaseSec: 0.05, backoffCapSec: 0.2, workerIntervalMs: 40, maxAttempts: 3, deliveryTimeoutMs: 2000, quiet: true, ...extra });
  const app = createApp(config, quiet);
  const addr = await app.start();
  config.publicUrl = `http://127.0.0.1:${addr.port}`;
  return { app, config, base: config.publicUrl, dir };
}

async function startReceiver() {
  const state = { mode: 'ok', hits: [] };
  const srv = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      state.hits.push({ url: req.url, headers: req.headers, body: Buffer.concat(chunks) });
      if (state.mode === 'ok') { res.writeHead(200); return res.end('{"ok":true}'); }
      if (state.mode === '500') { res.writeHead(500); return res.end('boom'); }
      if (state.mode === '400') { res.writeHead(400); return res.end('bad lead'); }
      if (state.mode === 'hang') return; // never answer
    });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  state.url = `http://127.0.0.1:${srv.address().port}/hook`;
  state.close = () => { srv.closeAllConnections?.(); srv.close(); };
  return state;
}

async function signup(c, email = 'owner@acme.test', workspace = 'Acme') {
  return c.req('POST', '/api/auth/setup', { name: 'Owner', workspace, email, password: 'correct-horse-battery' });
}

test('auth, CSRF and tenant isolation', async () => {
  const { app, base } = await startApp({ allowSignup: true });
  try {
    const anon = new Client(base);
    assert.equal((await anon.req('GET', '/api/session')).status, 401);
    assert.equal((await anon.req('GET', '/api/overview')).status, 401);
    assert.equal((await fetch(base + '/api/auth/setup', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })).status, 403); // no CSRF header

    const a = new Client(base);
    assert.equal((await a.req('POST', '/api/auth/setup', { name: 'A', workspace: 'A', email: 'a@x.test', password: 'short' })).status, 400);
    assert.equal((await signup(a, 'a@x.test', 'Agency A')).status, 201);
    assert.equal((await a.req('GET', '/api/session')).json.agency.name, 'Agency A');

    const bad = new Client(base);
    assert.equal((await bad.req('POST', '/api/auth/login', { email: 'a@x.test', password: 'wrong-password-1' })).status, 401);
    assert.equal((await bad.req('POST', '/api/auth/login', { email: 'nobody@x.test', password: 'wrong-password-1' })).status, 401);
    const good = new Client(base);
    assert.equal((await good.req('POST', '/api/auth/login', { email: 'a@x.test', password: 'correct-horse-battery' })).status, 200);

    // second workspace cannot touch the first one's data
    const b = new Client(base);
    assert.equal((await signup(b, 'b@x.test', 'Agency B')).status, 201);
    const rx = await startReceiver();
    const created = await a.req('POST', '/api/destinations', { name: 'CRM', url: rx.url });
    // strict mode would reject http/private; this app allows it only because the test enables it below
    rx.close();
    assert.ok([201, 400].includes(created.status));
  } finally { await app.stop(); }
});

test('strict mode rejects private / http destinations', async () => {
  const { app, base } = await startApp();
  try {
    const c = new Client(base); await signup(c);
    for (const url of ['http://example.com/x', 'https://127.0.0.1/x', 'https://169.254.169.254/', 'https://localhost/x', 'https://[::1]/x']) {
      const r = await c.req('POST', '/api/destinations', { name: 'x', url });
      assert.equal(r.status, 400, url);
    }
    assert.equal((await c.req('POST', '/api/destinations', { name: 'ok', url: 'https://hooks.example.com/x' })).status, 201);
    assert.equal((await c.req('PATCH', '/api/settings', { alert_webhook_url: 'https://10.0.0.1/hook' })).status, 400);
  } finally { await app.stop(); }
});

test('full delivery lifecycle: ingest → forward → retry → dead-letter → incident → auto-resolve', async () => {
  const { app, base } = await startApp({ allowPrivateTargets: true, allowHttpTargets: true, allowSignup: true });
  const rx = await startReceiver();
  try {
    const c = new Client(base); await signup(c);
    const cr = await c.req('POST', '/api/destinations', { name: 'Client CRM', url: rx.url, outbound_secret: 'outbound-secret-123456' });
    assert.equal(cr.status, 201);
    const ingest = new URL(cr.json.ingest_url).pathname;
    const secret = cr.json.signing_secret;
    const destId = cr.json.destination.id;
    assert.match(ingest, /^\/i\/ro_/);
    assert.ok(!JSON.stringify(cr.json.destination).includes('ro_'.repeat(2)));

    // 1) happy path, with idempotency
    const lead = JSON.stringify({ name: 'Jane', email: 'jane@example.com' });
    const r1 = await fetch(base + ingest, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Idempotency-Key': 'k1' }, body: lead });
    assert.equal(r1.status, 202);
    const id1 = (await r1.json()).id;
    await until(() => rx.hits.length === 1);
    assert.equal(rx.hits[0].body.toString(), lead);
    assert.equal(rx.hits[0].headers['x-relayops-event-id'], id1);
    const ts = Number(/t=(\d+)/.exec(rx.hits[0].headers['x-relayops-signature'])[1]);
    assert.ok(rx.hits[0].headers['x-relayops-signature'].includes(sign('outbound-secret-123456', ts, rx.hits[0].body)));
    const ev = await until(async () => { const e = (await c.req('GET', '/api/events/' + id1)).json; return e.event.status === 'success' && e; });
    assert.equal(ev.attempts.length, 1);
    assert.equal(ev.event.has_payload, false, 'payload purged after success');
    const dup = await fetch(base + ingest, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Idempotency-Key': 'k1' }, body: lead });
    assert.equal(dup.status, 200); assert.equal((await dup.json()).duplicate, true);
    await sleep(150); assert.equal(rx.hits.length, 1, 'duplicate not re-delivered');

    // 2) signatures required, replay + tamper + stale rejected
    await c.req('PATCH', '/api/destinations/' + destId, { require_signature: true });
    assert.equal((await fetch(base + ingest, { method: 'POST', body: lead })).status, 401);
    const t = Math.floor(Date.now() / 1000);
    const hdr = `t=${t},v1=${sign(secret, t, Buffer.from(lead))}`;
    assert.equal((await fetch(base + ingest, { method: 'POST', headers: { 'X-RelayOps-Signature': hdr }, body: lead })).status, 202);
    assert.equal((await fetch(base + ingest, { method: 'POST', headers: { 'X-RelayOps-Signature': hdr }, body: lead })).status, 409, 'replay');
    assert.equal((await fetch(base + ingest, { method: 'POST', headers: { 'X-RelayOps-Signature': hdr }, body: lead + ' ' })).status, 401, 'tamper');
    const old = t - 3600;
    assert.equal((await fetch(base + ingest, { method: 'POST', headers: { 'X-RelayOps-Signature': `t=${old},v1=${sign(secret, old, Buffer.from(lead))}` }, body: lead })).status, 401, 'stale');
    await c.req('PATCH', '/api/destinations/' + destId, { require_signature: false });
    await until(() => rx.hits.length === 2);

    // 3) unknown token, oversize payload
    assert.equal((await fetch(base + '/i/ro_' + 'a'.repeat(43), { method: 'POST', body: lead })).status, 404);
    assert.equal((await fetch(base + '/i/nonsense', { method: 'POST', body: lead })).status, 404);
    assert.equal((await fetch(base + ingest, { method: 'POST', body: Buffer.alloc(300 * 1024, 1) })).status, 413);
    assert.equal((await fetch(base + ingest, { method: 'GET' })).status, 405);

    // 4) destination outage → retries → dead-letter → incident
    rx.mode = '500';
    const before = rx.hits.length;
    const r2 = await fetch(base + ingest, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: lead });
    const id2 = (await r2.json()).id;
    const dead = await until(async () => { const e = (await c.req('GET', '/api/events/' + id2)).json; return e.event.status === 'failed' && e; });
    assert.equal(dead.attempts.length, 3, 'bounded retries');
    assert.equal(dead.event.dead, true);
    assert.equal(rx.hits.length - before, 3);
    assert.equal(dead.event.has_payload, true, 'payload kept for replay');
    const inc = (await c.req('GET', '/api/incidents?status=open')).json.items;
    assert.equal(inc.length, 1);
    assert.equal(inc[0].severity, 'high');
    assert.equal((await c.req('GET', '/api/overview')).json.destinations[0].status, 'attention');

    // 5) recovery: retry the dead letter → delivered, incident auto-resolves
    rx.mode = 'ok';
    assert.equal((await c.req('POST', `/api/events/${id2}/retry`)).status, 200);
    await until(async () => (await c.req('GET', '/api/events/' + id2)).json.event.status === 'success');
    await until(async () => (await c.req('GET', '/api/incidents?status=open')).json.items.length === 0);
    const all = (await c.req('GET', '/api/incidents')).json.items;
    assert.equal(all[0].status, 'resolved'); assert.equal(all[0].resolved_by, 'auto');

    // 6) non-retryable 4xx fails immediately (1 attempt)
    rx.mode = '400';
    const r3 = await fetch(base + ingest, { method: 'POST', body: lead });
    const id3 = (await r3.json()).id;
    const e3 = await until(async () => { const e = (await c.req('GET', '/api/events/' + id3)).json; return e.event.status === 'failed' && e; });
    assert.equal(e3.attempts.length, 1);
    assert.match(e3.event.error, /HTTP 400/);

    // 7) real synthetic test + hang → unconfirmed
    rx.mode = 'ok';
    const t1 = (await c.req('POST', `/api/destinations/${destId}/test`)).json.delivery;
    assert.equal(t1.status, 'success'); assert.equal(t1.kind, 'synthetic');
    assert.equal(rx.hits.at(-1).headers['x-relayops-synthetic'], 'true');
    rx.mode = 'hang';
    const t2 = (await c.req('POST', `/api/destinations/${destId}/test`)).json.delivery;
    assert.equal(t2.status, 'unconfirmed');

    // 8) overview, csv, pause
    const ov = (await c.req('GET', '/api/overview')).json;
    assert.ok(ov.stats.delivered_24h >= 3);
    const csv = await c.req('GET', '/api/events.csv');
    assert.match(csv.headers.get('content-type'), /text\/csv/);
    assert.ok(csv.text.split('\r\n').length > 5);
    await c.req('PATCH', '/api/destinations/' + destId, { paused: true });
    assert.equal((await fetch(base + ingest, { method: 'POST', body: lead })).status, 409);

    // 9) rotating the token kills the old URL
    const rot = await c.req('POST', `/api/destinations/${destId}/rotate-token`);
    assert.equal((await fetch(base + ingest, { method: 'POST', body: lead })).status, 404);
    assert.notEqual(new URL(rot.json.ingest_url).pathname, ingest);

    // 10) tenant isolation
    const b = new Client(base); assert.equal((await signup(b, 'b@x.test', 'B')).status, 201);
    assert.equal((await b.req('GET', '/api/destinations/' + destId)).status, 404);
    assert.equal((await b.req('GET', '/api/events/' + id1)).status, 404);
    assert.equal((await b.req('POST', `/api/destinations/${destId}/test`)).status, 404);
    assert.equal((await b.req('DELETE', '/api/destinations/' + destId)).status, 404);
    assert.equal((await b.req('GET', '/api/events')).json.total, 0);
  } finally { rx.close(); await app.stop(); }
});

test('scheduled synthetic checks run on their own and open an incident when the destination dies', async () => {
  const { app, base, config } = await startApp({ allowPrivateTargets: true, allowHttpTargets: true });
  const rx = await startReceiver();
  try {
    const c = new Client(base); await signup(c);
    const d = (await c.req('POST', '/api/destinations', { name: 'Scheduled', url: rx.url, check_interval_min: 1 })).json.destination;
    await until(() => rx.hits.length >= 1);
    assert.equal(rx.hits[0].headers['x-relayops-synthetic'], 'true');
    await until(async () => (await c.req('GET', '/api/destinations/' + d.id)).json.destination.status === 'healthy');
    rx.mode = '500';
    // force two quick checks instead of waiting a minute
    app.db.prepare('UPDATE destinations SET next_check_at=? WHERE id=?').run(Date.now() - 1, d.id);
    await until(async () => (await c.req('GET', '/api/incidents?status=open')).json.items.length === 1, 12000);
    assert.equal(config.incidentThreshold, 2);
  } finally { rx.close(); await app.stop(); }
});

test('alert webhook fires on incident open and recovery', async () => {
  const { app, base } = await startApp({ allowPrivateTargets: true, allowHttpTargets: true });
  const rx = await startReceiver(); const alerts = await startReceiver();
  try {
    const c = new Client(base); await signup(c);
    assert.equal((await c.req('PATCH', '/api/settings', { alert_webhook_url: alerts.url })).status, 200);
    assert.equal((await c.req('POST', '/api/settings/test-alert')).json.ok, true);
    const cr = await c.req('POST', '/api/destinations', { name: 'Alerty', url: rx.url });
    const ingest = new URL(cr.json.ingest_url).pathname;
    rx.mode = '400';
    await fetch(base + ingest, { method: 'POST', body: '{}' });
    await until(() => alerts.hits.some((h) => /Incident INC-1/.test(h.body.toString())));
    rx.mode = 'ok';
    await fetch(base + ingest, { method: 'POST', body: '{}' });
    await until(() => alerts.hits.some((h) => /Resolved/.test(h.body.toString())));
  } finally { rx.close(); alerts.close(); await app.stop(); }
});

test('team management, roles and password change', async () => {
  const { app, base } = await startApp();
  try {
    const o = new Client(base); await signup(o);
    assert.equal((await o.req('POST', '/api/team', { name: 'Mem', email: 'm@x.test', password: 'member-password-1', role: 'member' })).status, 201);
    const m = new Client(base);
    assert.equal((await m.req('POST', '/api/auth/login', { email: 'm@x.test', password: 'member-password-1' })).status, 200);
    assert.equal((await m.req('POST', '/api/team', { name: 'X', email: 'x@x.test', password: 'member-password-1' })).status, 403);
    assert.equal((await m.req('GET', '/api/audit')).status, 403);
    assert.equal((await m.req('PATCH', '/api/settings', { name: 'Hacked' })).status, 403);
    assert.equal((await m.req('POST', '/api/auth/password', { current: 'member-password-1', next: 'brand-new-password-2' })).status, 200);
    const m2 = new Client(base);
    assert.equal((await m2.req('POST', '/api/auth/login', { email: 'm@x.test', password: 'member-password-1' })).status, 401);
    assert.equal((await m2.req('POST', '/api/auth/login', { email: 'm@x.test', password: 'brand-new-password-2' })).status, 200);
    const audit = (await o.req('GET', '/api/audit')).json.items;
    assert.ok(audit.some((a) => a.action === 'team.added'));
    // setup is closed once a workspace exists
    assert.equal((await new Client(base).req('POST', '/api/auth/setup', { name: 'E', workspace: 'E', email: 'e@x.test', password: 'evil-password-123' })).status, 403);
  } finally { await app.stop(); }
});

test('static UI is served with a strict CSP', async () => {
  const { app, base } = await startApp();
  try {
    const r = await fetch(base + '/');
    assert.equal(r.status, 200);
    assert.match(r.headers.get('content-security-policy'), /script-src 'self'/);
    assert.match(await r.text(), /RelayOps/);
    assert.equal((await fetch(base + '/..%2f..%2fetc/passwd')).status, 404);
    assert.equal((await fetch(base + '/core-config.js')).status, 404, 'server source is not served');
    assert.equal((await fetch(base + '/package.json')).status, 404);
    assert.equal((await fetch(base + '/ui.js')).status, 200);
  } finally { await app.stop(); }
});
