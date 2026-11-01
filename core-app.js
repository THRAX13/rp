'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');
const dbm = require('./core-db');
const { Engine } = require('./core-engine');
const { RateLimiter } = require('./core-ratelimit');
const A = require('./core-auth');
const S = require('./core-security');
const { newId, sha256, now, HttpError, str, csvCell } = require('./core-util');

const INTERVALS = [0, 1, 5, 15, 30, 60, 360, 1440];
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.json': 'application/json', '.webmanifest': 'application/manifest+json' };

function createApp(config, log = console) {
  const db = dbm.open(config.dbFile);
  const engine = new Engine({ db, config, log });
  const limiters = {
    ingestIp: new RateLimiter(600, 60000),
    ingestDest: new RateLimiter(config.ingestRatePerMin, 60000),
    ingestMiss: new RateLimiter(30, 60000),
    loginIp: new RateLimiter(30, 15 * 60000),
    loginEmail: new RateLimiter(10, 15 * 60000),
    signupIp: new RateLimiter(10, 60 * 60000),
  };
  const replay = new Map(); // signature nonce -> expiry
  const cookieName = config.secureCookies ? '__Host-ro_session' : 'ro_session';
  const publicDir = __dirname;
  const STATIC = new Set(['index.html', 'ui.js', 'ui.css', 'favicon.svg']);
  const staticCache = new Map();
  const routes = [];

  /* ───────── helpers ───────── */

  const clientIp = (req) => {
    if (config.trustProxy > 0) {
      const xff = String(req.headers['x-forwarded-for'] || '').split(',').map((s) => s.trim()).filter(Boolean);
      const ip = xff[xff.length - config.trustProxy];
      if (ip) return ip;
    }
    return (req.socket.remoteAddress || '').replace(/^::ffff:/, '');
  };

  function readBody(req, limit) {
    return new Promise((resolve, reject) => {
      const len = Number(req.headers['content-length']);
      if (Number.isFinite(len) && len > limit) return reject(new HttpError(413, `Payload exceeds ${limit} bytes`, 'payload_too_large'));
      const chunks = [];
      let size = 0;
      let failed = false;
      req.on('data', (c) => {
        if (failed) return;
        size += c.length;
        if (size > limit) { failed = true; chunks.length = 0; return reject(new HttpError(413, `Payload exceeds ${limit} bytes`, 'payload_too_large')); }
        chunks.push(c);
      });
      req.on('end', () => !failed && resolve(Buffer.concat(chunks)));
      req.on('error', (e) => !failed && reject(e));
    });
  }

  async function readJson(req, limit = 64 * 1024) {
    const buf = await readBody(req, limit);
    if (!buf.length) return {};
    const ct = String(req.headers['content-type'] || '');
    if (!ct.toLowerCase().startsWith('application/json')) throw new HttpError(415, 'Content-Type must be application/json', 'unsupported_media_type');
    try {
      const v = JSON.parse(buf.toString('utf8'));
      if (v === null || typeof v !== 'object' || Array.isArray(v)) throw new Error();
      return v;
    } catch (_) {
      throw new HttpError(400, 'Invalid JSON body', 'invalid_json');
    }
  }

  const baseHeaders = () => {
    const h = {
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'X-Frame-Options': 'DENY',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Resource-Policy': 'same-origin',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
      'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    };
    if (config.secureCookies) h['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';
    return h;
  };

  function sendJson(res, status, obj, extra = {}) {
    const body = JSON.stringify(obj);
    res.writeHead(status, { ...baseHeaders(), 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'Content-Length': Buffer.byteLength(body), ...extra });
    res.end(body);
  }

  function setSessionCookie(res, token, maxAgeSec) {
    const attrs = [`${cookieName}=${token}`, 'Path=/', 'HttpOnly', 'SameSite=Strict', `Max-Age=${maxAgeSec}`];
    if (config.secureCookies) attrs.push('Secure');
    res.setHeader('Set-Cookie', attrs.join('; '));
  }

  const add = (method, p, auth, handler) => {
    const re = new RegExp('^' + p.replace(/:([a-z]+)/g, '(?<$1>[^/]+)') + '$');
    routes.push({ method, re, auth, handler });
  };

  function aud(ctx, action, detail) {
    dbm.audit(db, ctx.agency?.id, ctx.user?.id, action, detail, ctx.ip);
  }

  const getDest = (ctx, id) => {
    const d = db.prepare('SELECT * FROM destinations WHERE id=? AND agency_id=?').get(id, ctx.agency.id);
    if (!d) throw new HttpError(404, 'Destination not found', 'not_found');
    return d;
  };

  const pubDest = (d, stats) => ({
    id: d.id, name: d.name, url: d.url, check_url: d.check_url, token_hint: d.token_hint,
    require_signature: !!d.require_signature, has_inbound_secret: !!d.inbound_secret_enc, has_outbound_secret: !!d.outbound_secret_enc,
    check_interval_min: d.check_interval_min, paused: !!d.paused, status: d.paused ? 'paused' : d.status,
    consecutive_failures: d.consecutive_failures, last_checked_at: d.last_checked_at, last_success_at: d.last_success_at,
    last_error: d.last_error, created_at: d.created_at, stats24h: stats || { total: 0, ok: 0 },
  });

  const pubDelivery = (r) => ({
    id: r.id, destination_id: r.destination_id, destination_name: r.destination_name, kind: r.kind, status: r.status,
    attempts: r.attempts, max_attempts: r.max_attempts, next_attempt_at: r.next_attempt_at, http_status: r.http_status,
    latency_ms: r.latency_ms, error: r.error, response_snippet: r.response_snippet, payload_bytes: r.payload_bytes,
    payload_sha256: r.payload_sha256, has_payload: !!r.has_payload, source_ip: r.source_ip, idempotency_key: r.idempotency_key,
    created_at: r.created_at, completed_at: r.completed_at,
    dead: r.status !== 'success' && r.status !== 'queued' && r.attempts >= r.max_attempts && r.kind === 'lead',
  });

  const validateUrlField = (v, name) => {
    const c = S.validateTargetUrl(v, { allowHttp: config.allowHttpTargets, allowPrivate: config.allowPrivateTargets });
    if (!c.ok) throw new HttpError(400, `${name}: ${c.error}`, 'invalid_url');
    return c.url.toString();
  };

  const newTokenPair = () => {
    const token = S.randomToken('ro_', 32);
    return { token, hash: sha256(token), hint: token.slice(0, 7) + '…' + token.slice(-3), url: `${config.publicUrl}/i/${token}` };
  };

  /* ───────── public: health, bootstrap, auth ───────── */

  add('GET', '/api/health', 'none', () => {
    db.prepare('SELECT 1').get();
    return { ok: true, version: config.version };
  });

  add('GET', '/api/bootstrap', 'none', () => ({
    setupRequired: db.prepare('SELECT COUNT(*) c FROM users').get().c === 0,
    allowSignup: config.allowSignup,
    version: config.version,
  }));

  async function startSession(ctx, user) {
    const s = A.createSession(db, user, { ip: ctx.ip, ua: ctx.req.headers['user-agent'], days: config.sessionDays });
    setSessionCookie(ctx.res, s.token, config.sessionDays * 86400);
    db.prepare('UPDATE users SET last_login_at=? WHERE id=?').run(now(), user.id);
  }

  add('POST', '/api/auth/setup', 'none', async (ctx) => {
    const hasUsers = db.prepare('SELECT COUNT(*) c FROM users').get().c > 0;
    if (hasUsers && !config.allowSignup) throw new HttpError(403, 'Sign-up is disabled. Ask a workspace owner to add you.', 'signup_disabled');
    if (!limiters.signupIp.hit(ctx.ip).ok) throw new HttpError(429, 'Too many sign-ups from this address', 'rate_limited');
    const b = ctx.body;
    const name = str(b.name, { name: 'Name', min: 1, max: 80 });
    const workspace = str(b.workspace, { name: 'Workspace name', min: 1, max: 80 });
    const email = str(b.email, { name: 'Email', min: 3, max: 200 }).toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new HttpError(400, 'Enter a valid email address', 'invalid_input');
    const pwErr = A.checkPasswordPolicy(b.password);
    if (pwErr) throw new HttpError(400, pwErr, 'weak_password');
    if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email)) throw new HttpError(409, 'An account with this email already exists', 'email_taken');
    const hash = await A.hashPassword(b.password);
    const agencyId = newId('agy_');
    const user = { id: newId('usr_'), agency_id: agencyId };
    dbm.tx(db, () => {
      if (!hasUsers && db.prepare('SELECT COUNT(*) c FROM users').get().c > 0) throw new HttpError(409, 'Setup already completed', 'conflict');
      db.prepare('INSERT INTO agencies(id,name,created_at) VALUES(?,?,?)').run(agencyId, workspace, now());
      db.prepare('INSERT INTO users(id,agency_id,email,name,password_hash,role,created_at) VALUES(?,?,?,?,?,?,?)').run(user.id, agencyId, email, name, hash, 'owner', now());
    });
    await startSession(ctx, user);
    dbm.audit(db, agencyId, user.id, 'workspace.created', workspace, ctx.ip);
    ctx.json(201, { ok: true });
  });

  add('POST', '/api/auth/login', 'none', async (ctx) => {
    const email = String(ctx.body.email || '').trim().toLowerCase().slice(0, 200);
    const pw = String(ctx.body.password || '').slice(0, 200);
    if (!limiters.loginIp.hit(ctx.ip).ok || !limiters.loginEmail.hit(email).ok)
      throw new HttpError(429, 'Too many sign-in attempts. Try again in a few minutes.', 'rate_limited');
    const u = db.prepare('SELECT * FROM users WHERE email=?').get(email);
    if (!u) { await A.dummyVerify(pw); throw new HttpError(401, 'Incorrect email or password', 'bad_credentials'); }
    if (!(await A.verifyPassword(pw, u.password_hash))) {
      dbm.audit(db, u.agency_id, u.id, 'auth.login_failed', null, ctx.ip);
      throw new HttpError(401, 'Incorrect email or password', 'bad_credentials');
    }
    await startSession(ctx, u);
    dbm.audit(db, u.agency_id, u.id, 'auth.login', null, ctx.ip);
    ctx.json(200, { ok: true });
  });

  add('POST', '/api/auth/logout', 'user', (ctx) => {
    db.prepare('DELETE FROM sessions WHERE token_hash=?').run(ctx.session.token_hash);
    setSessionCookie(ctx.res, '', 0);
    ctx.json(200, { ok: true });
  });

  add('GET', '/api/session', 'user', (ctx) => ({
    user: { id: ctx.user.id, name: ctx.user.name, email: ctx.user.email, role: ctx.user.role },
    agency: { id: ctx.agency.id, name: ctx.agency.name },
    config: {
      publicUrl: config.publicUrl, version: config.version, maxAttempts: config.maxAttempts, maxPayloadBytes: config.maxPayloadBytes,
      allowHttpTargets: config.allowHttpTargets, allowPrivateTargets: config.allowPrivateTargets, intervals: INTERVALS,
    },
  }));

  add('POST', '/api/auth/password', 'user', async (ctx) => {
    const u = db.prepare('SELECT * FROM users WHERE id=?').get(ctx.user.id);
    if (!limiters.loginEmail.hit(u.email).ok) throw new HttpError(429, 'Too many attempts', 'rate_limited');
    if (!(await A.verifyPassword(String(ctx.body.current || ''), u.password_hash))) throw new HttpError(403, 'Current password is incorrect', 'bad_credentials');
    const err = A.checkPasswordPolicy(ctx.body.next);
    if (err) throw new HttpError(400, err, 'weak_password');
    db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(await A.hashPassword(ctx.body.next), u.id);
    db.prepare('DELETE FROM sessions WHERE user_id=? AND token_hash!=?').run(u.id, ctx.session.token_hash);
    aud(ctx, 'auth.password_changed');
    return { ok: true };
  });

  /* ───────── overview ───────── */

  add('GET', '/api/overview', 'user', (ctx) => {
    const aid = ctx.agency.id;
    const since = now() - 86400000;
    const counts = Object.fromEntries(db.prepare('SELECT status, COUNT(*) c FROM deliveries WHERE agency_id=? AND created_at>=? GROUP BY status').all(aid, since).map((r) => [r.status, r.c]));
    const ok = counts.success || 0;
    const bad = (counts.failed || 0) + (counts.unconfirmed || 0);
    const lat = db.prepare("SELECT latency_ms l FROM deliveries WHERE agency_id=? AND created_at>=? AND status='success' AND latency_ms IS NOT NULL ORDER BY latency_ms LIMIT 5000").all(aid, since).map((r) => r.l);
    const hourMs = 3600000;
    const nowHour = Math.floor(now() / hourMs);
    const buckets = Array.from({ length: 24 }, (_, i) => ({ t: (nowHour - 23 + i) * hourMs, ok: 0, bad: 0 }));
    db.prepare("SELECT created_at/3600000 h, status, COUNT(*) c FROM deliveries WHERE agency_id=? AND created_at>=? AND status IN ('success','failed','unconfirmed') GROUP BY h,status").all(aid, buckets[0].t)
      .forEach((r) => { const b = buckets[r.h - (nowHour - 23)]; if (b) r.status === 'success' ? (b.ok += r.c) : (b.bad += r.c); });
    const dests = db.prepare('SELECT * FROM destinations WHERE agency_id=? ORDER BY created_at DESC').all(aid);
    const perDest = Object.fromEntries(db.prepare("SELECT destination_id d, COUNT(*) total, SUM(status='success') ok FROM deliveries WHERE agency_id=? AND created_at>=? AND status IN ('success','failed','unconfirmed') GROUP BY d").all(aid, since).map((r) => [r.d, { total: r.total, ok: r.ok }]));
    const recent = db.prepare('SELECT d.*, x.name destination_name, (d.payload IS NOT NULL) has_payload FROM deliveries d JOIN destinations x ON x.id=d.destination_id WHERE d.agency_id=? ORDER BY d.created_at DESC LIMIT 8').all(aid).map(pubDelivery);
    const openInc = db.prepare("SELECT COUNT(*) c FROM incidents WHERE agency_id=? AND status='open'").get(aid).c;
    return {
      stats: {
        destinations: dests.length, healthy: dests.filter((d) => !d.paused && d.status === 'healthy').length, open_incidents: openInc,
        delivered_24h: ok, failed_24h: bad, queued: counts.queued || 0,
        success_rate_24h: ok + bad ? ok / (ok + bad) : null,
        latency_avg_ms: lat.length ? Math.round(lat.reduce((a, b) => a + b, 0) / lat.length) : null,
        latency_p95_ms: lat.length ? lat[Math.min(lat.length - 1, Math.floor(lat.length * 0.95))] : null,
      },
      hourly: buckets,
      destinations: dests.map((d) => pubDest(d, perDest[d.id])),
      recent,
    };
  });

  /* ───────── destinations ───────── */

  add('GET', '/api/destinations', 'user', (ctx) => {
    const since = now() - 86400000;
    const per = Object.fromEntries(db.prepare("SELECT destination_id d, COUNT(*) total, SUM(status='success') ok FROM deliveries WHERE agency_id=? AND created_at>=? AND status IN ('success','failed','unconfirmed') GROUP BY d").all(ctx.agency.id, since).map((r) => [r.d, { total: r.total, ok: r.ok }]));
    return { items: db.prepare('SELECT * FROM destinations WHERE agency_id=? ORDER BY created_at DESC').all(ctx.agency.id).map((d) => pubDest(d, per[d.id])) };
  });

  function parseDestBody(b, existing) {
    const out = {};
    if (!existing || b.name !== undefined) out.name = str(b.name, { name: 'Name', min: 1, max: 80 });
    if (!existing || b.url !== undefined) out.url = validateUrlField(b.url, 'Endpoint URL');
    if (b.check_url !== undefined) out.check_url = b.check_url ? validateUrlField(b.check_url, 'Check URL') : null;
    if (b.check_interval_min !== undefined) {
      const n = Number(b.check_interval_min);
      if (!INTERVALS.includes(n)) throw new HttpError(400, 'Invalid check interval', 'invalid_input');
      out.check_interval_min = n;
    }
    if (b.require_signature !== undefined) out.require_signature = b.require_signature ? 1 : 0;
    if (b.outbound_secret !== undefined) {
      out.outbound_secret = b.outbound_secret ? str(b.outbound_secret, { name: 'Outbound signing secret', min: 16, max: 200 }) : null;
    }
    return out;
  }

  add('POST', '/api/destinations', 'user', (ctx) => {
    if (db.prepare('SELECT COUNT(*) c FROM destinations WHERE agency_id=?').get(ctx.agency.id).c >= 200) throw new HttpError(400, 'Destination limit reached (200)', 'limit');
    const p = parseDestBody(ctx.body, null);
    const tk = newTokenPair();
    const inbound = S.randomToken('whsec_', 24);
    const id = newId('dst_');
    const interval = p.check_interval_min || 0;
    db.prepare(
      `INSERT INTO destinations(id,agency_id,name,url,check_url,token_hash,token_hint,inbound_secret_enc,require_signature,outbound_secret_enc,check_interval_min,next_check_at,created_at)
       VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).run(id, ctx.agency.id, p.name, p.url, p.check_url || null, tk.hash, tk.hint, S.encrypt(config.secretKey, inbound), p.require_signature || 0,
      p.outbound_secret ? S.encrypt(config.secretKey, p.outbound_secret) : null, interval, interval ? now() : null, now());
    aud(ctx, 'destination.created', p.name);
    ctx.json(201, { destination: pubDest(db.prepare('SELECT * FROM destinations WHERE id=?').get(id)), ingest_url: tk.url, signing_secret: inbound });
  });

  add('GET', '/api/destinations/:id', 'user', (ctx) => ({ destination: pubDest(getDest(ctx, ctx.params.id)) }));

  add('PATCH', '/api/destinations/:id', 'user', (ctx) => {
    const d = getDest(ctx, ctx.params.id);
    const p = parseDestBody(ctx.body, d);
    const sets = []; const args = [];
    const setf = (col, val) => { sets.push(`${col}=?`); args.push(val); };
    if (p.name !== undefined) setf('name', p.name);
    if (p.url !== undefined) setf('url', p.url);
    if (p.check_url !== undefined) setf('check_url', p.check_url);
    if (p.require_signature !== undefined) setf('require_signature', p.require_signature);
    if (p.outbound_secret !== undefined) setf('outbound_secret_enc', p.outbound_secret ? S.encrypt(config.secretKey, p.outbound_secret) : null);
    if (p.check_interval_min !== undefined) { setf('check_interval_min', p.check_interval_min); setf('next_check_at', p.check_interval_min ? now() : null); }
    if (ctx.body.paused !== undefined) setf('paused', ctx.body.paused ? 1 : 0);
    if (sets.length) db.prepare(`UPDATE destinations SET ${sets.join(',')} WHERE id=?`).run(...args, d.id);
    aud(ctx, ctx.body.paused !== undefined && Object.keys(ctx.body).length === 1 ? (ctx.body.paused ? 'destination.paused' : 'destination.resumed') : 'destination.updated', d.name);
    return { destination: pubDest(db.prepare('SELECT * FROM destinations WHERE id=?').get(d.id)) };
  });

  add('DELETE', '/api/destinations/:id', 'user', (ctx) => {
    const d = getDest(ctx, ctx.params.id);
    db.prepare('DELETE FROM destinations WHERE id=?').run(d.id);
    aud(ctx, 'destination.deleted', d.name);
    return { ok: true };
  });

  add('POST', '/api/destinations/:id/rotate-token', 'user', (ctx) => {
    const d = getDest(ctx, ctx.params.id);
    const tk = newTokenPair();
    db.prepare('UPDATE destinations SET token_hash=?,token_hint=? WHERE id=?').run(tk.hash, tk.hint, d.id);
    aud(ctx, 'destination.token_rotated', d.name);
    return { ingest_url: tk.url, destination: pubDest(db.prepare('SELECT * FROM destinations WHERE id=?').get(d.id)) };
  });

  add('POST', '/api/destinations/:id/rotate-secret', 'user', (ctx) => {
    const d = getDest(ctx, ctx.params.id);
    const sec = S.randomToken('whsec_', 24);
    db.prepare('UPDATE destinations SET inbound_secret_enc=? WHERE id=?').run(S.encrypt(config.secretKey, sec), d.id);
    aud(ctx, 'destination.secret_rotated', d.name);
    return { signing_secret: sec };
  });

  const testLimiter = new RateLimiter(20, 60000);
  add('POST', '/api/destinations/:id/test', 'user', async (ctx) => {
    const d = getDest(ctx, ctx.params.id);
    if (!testLimiter.hit(ctx.agency.id).ok) throw new HttpError(429, 'Too many tests — wait a minute', 'rate_limited');
    const row = await engine.checkNow(d);
    aud(ctx, 'destination.tested', `${d.name} → ${row.status}`);
    return { delivery: pubDelivery({ ...row, destination_name: d.name, has_payload: !!row.payload }) };
  });

  /* ───────── events ───────── */

  function eventFilter(q, agencyId) {
    const where = ['d.agency_id=?']; const args = [agencyId];
    if (['success', 'failed', 'unconfirmed', 'queued'].includes(q.status)) { where.push('d.status=?'); args.push(q.status); }
    if (q.destination) { where.push('d.destination_id=?'); args.push(q.destination); }
    if (['lead', 'synthetic'].includes(q.kind)) { where.push('d.kind=?'); args.push(q.kind); }
    if (q.q) {
      const like = '%' + String(q.q).slice(0, 100).replace(/[\\%_]/g, '\\$&') + '%';
      where.push("(d.id LIKE ? ESCAPE '\\' OR d.error LIKE ? ESCAPE '\\' OR d.idempotency_key LIKE ? ESCAPE '\\')");
      args.push(like, like, like);
    }
    return { sql: where.join(' AND '), args };
  }

  add('GET', '/api/events', 'user', (ctx) => {
    const f = eventFilter(ctx.query, ctx.agency.id);
    const limit = Math.min(200, Math.max(1, parseInt(ctx.query.limit, 10) || 50));
    const offset = Math.max(0, parseInt(ctx.query.offset, 10) || 0);
    const total = db.prepare(`SELECT COUNT(*) c FROM deliveries d WHERE ${f.sql}`).get(...f.args).c;
    const items = db.prepare(`SELECT d.*, x.name destination_name, (d.payload IS NOT NULL) has_payload FROM deliveries d JOIN destinations x ON x.id=d.destination_id WHERE ${f.sql} ORDER BY d.created_at DESC LIMIT ? OFFSET ?`).all(...f.args, limit, offset).map(pubDelivery);
    return { items, total, limit, offset };
  });

  add('GET', '/api/events.csv', 'user', (ctx) => {
    const f = eventFilter(ctx.query, ctx.agency.id);
    const rows = db.prepare(`SELECT d.*, x.name destination_name FROM deliveries d JOIN destinations x ON x.id=d.destination_id WHERE ${f.sql} ORDER BY d.created_at DESC LIMIT 20000`).all(...f.args);
    const head = ['Event ID', 'Time (UTC)', 'Destination', 'Kind', 'Result', 'Attempts', 'HTTP status', 'Latency (ms)', 'Error', 'Payload bytes', 'Payload SHA-256', 'Idempotency key'];
    const lines = [head.map(csvCell).join(',')];
    for (const r of rows) lines.push([r.id, new Date(r.created_at).toISOString(), r.destination_name, r.kind, r.status, r.attempts, r.http_status, r.latency_ms, r.error, r.payload_bytes, r.payload_sha256, r.idempotency_key].map(csvCell).join(','));
    const body = '﻿' + lines.join('\r\n') + '\r\n';
    ctx.res.writeHead(200, { ...baseHeaders(), 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="relayops-events.csv"', 'Cache-Control': 'no-store' });
    ctx.res.end(body);
    aud(ctx, 'events.exported', `${rows.length} rows`);
  });

  add('GET', '/api/events/:id', 'user', (ctx) => {
    const r = db.prepare('SELECT d.*, x.name destination_name, (d.payload IS NOT NULL) has_payload FROM deliveries d JOIN destinations x ON x.id=d.destination_id WHERE d.id=? AND d.agency_id=?').get(ctx.params.id, ctx.agency.id);
    if (!r) throw new HttpError(404, 'Event not found', 'not_found');
    const attempts = db.prepare('SELECT n,result,http_status,latency_ms,error,response_snippet,created_at FROM attempts WHERE delivery_id=? ORDER BY n').all(r.id);
    return { event: pubDelivery(r), attempts };
  });

  add('POST', '/api/events/:id/retry', 'user', (ctx) => {
    const r = db.prepare('SELECT * FROM deliveries WHERE id=? AND agency_id=?').get(ctx.params.id, ctx.agency.id);
    if (!r) throw new HttpError(404, 'Event not found', 'not_found');
    if (r.status === 'queued' || r.status === 'success') throw new HttpError(409, 'Only failed events can be retried', 'conflict');
    if (!r.payload) throw new HttpError(409, 'The payload is no longer stored, so this event cannot be re-delivered', 'gone');
    db.prepare("UPDATE deliveries SET status='queued',max_attempts=attempts+?,next_attempt_at=?,completed_at=NULL WHERE id=?").run(config.maxAttempts, now(), r.id);
    engine.kick(r.id);
    aud(ctx, 'event.retried', r.id);
    return { ok: true };
  });

  /* ───────── incidents ───────── */

  add('GET', '/api/incidents', 'user', (ctx) => {
    const open = ctx.query.status === 'open';
    const rows = db.prepare(`SELECT i.*, x.name destination_name FROM incidents i JOIN destinations x ON x.id=i.destination_id WHERE i.agency_id=? ${open ? "AND i.status='open'" : ''} ORDER BY i.opened_at DESC LIMIT 200`).all(ctx.agency.id);
    return { items: rows.map((i) => ({ id: i.id, number: i.number, destination_id: i.destination_id, destination_name: i.destination_name, severity: i.severity, status: i.status, title: i.title, detail: i.detail, failure_count: i.failure_count, delivery_id: i.delivery_id, opened_at: i.opened_at, resolved_at: i.resolved_at, resolved_by: i.resolved_by })) };
  });

  add('POST', '/api/incidents/:id/resolve', 'user', (ctx) => {
    const i = db.prepare("SELECT * FROM incidents WHERE id=? AND agency_id=? AND status='open'").get(ctx.params.id, ctx.agency.id);
    if (!i) throw new HttpError(404, 'Open incident not found', 'not_found');
    db.prepare("UPDATE incidents SET status='resolved',resolved_at=?,resolved_by=? WHERE id=?").run(now(), ctx.user.id, i.id);
    aud(ctx, 'incident.resolved', `INC-${i.number}`);
    return { ok: true };
  });

  /* ───────── settings, team, audit ───────── */

  const ownerOnly = (ctx) => { if (ctx.user.role !== 'owner') throw new HttpError(403, 'Only workspace owners can do this', 'forbidden'); };

  add('GET', '/api/settings', 'user', (ctx) => {
    const a = db.prepare('SELECT name, alert_webhook_url FROM agencies WHERE id=?').get(ctx.agency.id);
    return { name: a.name, alert_webhook_url: a.alert_webhook_url, retention_days: config.retentionDays, payload_retention_days: config.payloadRetentionDays };
  });

  add('PATCH', '/api/settings', 'user', (ctx) => {
    ownerOnly(ctx);
    if (ctx.body.name !== undefined) db.prepare('UPDATE agencies SET name=? WHERE id=?').run(str(ctx.body.name, { name: 'Workspace name', min: 1, max: 80 }), ctx.agency.id);
    if (ctx.body.alert_webhook_url !== undefined) {
      const v = ctx.body.alert_webhook_url ? validateUrlField(ctx.body.alert_webhook_url, 'Alert webhook URL') : null;
      db.prepare('UPDATE agencies SET alert_webhook_url=? WHERE id=?').run(v, ctx.agency.id);
    }
    aud(ctx, 'settings.updated');
    return { ok: true };
  });

  add('POST', '/api/settings/test-alert', 'user', async (ctx) => {
    ownerOnly(ctx);
    const a = db.prepare('SELECT name, alert_webhook_url FROM agencies WHERE id=?').get(ctx.agency.id);
    if (!a.alert_webhook_url) throw new HttpError(400, 'Save an alert webhook URL first', 'invalid_input');
    const r = await engine.postAlert(a, { event: 'test', text: '✅ RelayOps test alert — alerts are working.', content: '✅ RelayOps test alert — alerts are working.', workspace: a.name });
    return r;
  });

  add('GET', '/api/team', 'user', (ctx) => ({
    items: db.prepare('SELECT id,name,email,role,created_at,last_login_at FROM users WHERE agency_id=? ORDER BY created_at').all(ctx.agency.id),
  }));

  add('POST', '/api/team', 'user', async (ctx) => {
    ownerOnly(ctx);
    const b = ctx.body;
    const name = str(b.name, { name: 'Name', min: 1, max: 80 });
    const email = str(b.email, { name: 'Email', min: 3, max: 200 }).toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new HttpError(400, 'Enter a valid email address', 'invalid_input');
    const err = A.checkPasswordPolicy(b.password);
    if (err) throw new HttpError(400, err, 'weak_password');
    const role = b.role === 'owner' ? 'owner' : 'member';
    if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email)) throw new HttpError(409, 'An account with this email already exists', 'email_taken');
    const id = newId('usr_');
    db.prepare('INSERT INTO users(id,agency_id,email,name,password_hash,role,created_at) VALUES(?,?,?,?,?,?,?)').run(id, ctx.agency.id, email, name, await A.hashPassword(b.password), role, now());
    aud(ctx, 'team.added', `${email} (${role})`);
    ctx.json(201, { ok: true, id });
  });

  add('DELETE', '/api/team/:id', 'user', (ctx) => {
    ownerOnly(ctx);
    if (ctx.params.id === ctx.user.id) throw new HttpError(400, "You can't remove yourself", 'invalid_input');
    const u = db.prepare('SELECT * FROM users WHERE id=? AND agency_id=?').get(ctx.params.id, ctx.agency.id);
    if (!u) throw new HttpError(404, 'User not found', 'not_found');
    db.prepare('DELETE FROM users WHERE id=?').run(u.id);
    aud(ctx, 'team.removed', u.email);
    return { ok: true };
  });

  add('GET', '/api/audit', 'user', (ctx) => {
    ownerOnly(ctx);
    return { items: db.prepare('SELECT a.id,a.action,a.detail,a.ip,a.created_at,u.email user_email FROM audit a LEFT JOIN users u ON u.id=a.user_id WHERE a.agency_id=? ORDER BY a.id DESC LIMIT 100').all(ctx.agency.id) };
  });

  /* ───────── webhook ingest ───────── */

  async function ingest(req, res, token, ip) {
    if (!limiters.ingestIp.hit(ip).ok) throw new HttpError(429, 'Too many requests', 'rate_limited');
    const fail404 = () => {
      if (!limiters.ingestMiss.hit(ip).ok) throw new HttpError(429, 'Too many invalid tokens', 'rate_limited');
      throw new HttpError(404, 'Unknown ingest URL', 'not_found');
    };
    if (!/^ro_[A-Za-z0-9_-]{40,64}$/.test(token)) fail404();
    const dest = db.prepare('SELECT * FROM destinations WHERE token_hash=?').get(sha256(token));
    if (!dest) fail404();
    const lim = limiters.ingestDest.hit(dest.id);
    if (!lim.ok) { const e = new HttpError(429, 'Rate limit exceeded for this ingest URL', 'rate_limited'); e.retryAfter = lim.retryAfter; throw e; }
    if (dest.paused) throw new HttpError(409, 'This destination is paused', 'destination_paused');
    const body = await readBody(req, config.maxPayloadBytes);
    if (!body.length) throw new HttpError(400, 'Empty payload', 'empty_payload');

    const sigHeader = req.headers['x-relayops-signature'];
    if (dest.require_signature || sigHeader) {
      let secret;
      try { secret = S.decrypt(config.secretKey, dest.inbound_secret_enc); } catch (_) { throw new HttpError(500, 'Signing secret unavailable', 'server_error'); }
      const v = S.verifySignature(sigHeader, body, secret);
      if (!v.ok) throw new HttpError(401, `Signature check failed (${v.reason})`, v.reason);
      const key = dest.id + ':' + v.nonce;
      const t = now();
      if (replay.has(key) && replay.get(key) > t) throw new HttpError(409, 'Replayed request rejected', 'replay');
      replay.set(key, t + 600000);
      if (replay.size > 50000) for (const [k, exp] of replay) if (exp <= t) replay.delete(k);
    }

    let idem = req.headers['idempotency-key'];
    if (idem !== undefined) {
      idem = String(idem);
      if (!/^[\x21-\x7e]{1,128}$/.test(idem)) throw new HttpError(400, 'Invalid Idempotency-Key', 'invalid_input');
      const ex = db.prepare('SELECT id,status FROM deliveries WHERE destination_id=? AND idempotency_key=?').get(dest.id, idem);
      if (ex) return sendJson(res, 200, { id: ex.id, status: ex.status, duplicate: true });
    } else idem = null;

    if (db.prepare("SELECT COUNT(*) c FROM deliveries WHERE destination_id=? AND status='queued'").get(dest.id).c >= 5000)
      throw new HttpError(503, 'Delivery queue for this destination is full', 'queue_full');

    let ct = String(req.headers['content-type'] || '').slice(0, 200);
    if (!/^[\x20-\x7e]+$/.test(ct)) ct = 'application/octet-stream';
    let id;
    try {
      id = engine.enqueue({ dest, kind: 'lead', payload: body, contentType: ct, idempotencyKey: idem, sourceIp: ip });
    } catch (e) {
      if (idem && /UNIQUE/i.test(String(e.message))) {
        const ex = db.prepare('SELECT id,status FROM deliveries WHERE destination_id=? AND idempotency_key=?').get(dest.id, idem);
        if (ex) return sendJson(res, 200, { id: ex.id, status: ex.status, duplicate: true });
      }
      throw e;
    }
    engine.kick(id);
    sendJson(res, 202, { id, status: 'queued' });
  }

  /* ───────── static files ───────── */

  function serveStatic(req, res, pathname) {
    let rel = pathname === '/' ? '/index.html' : pathname;
    if (!STATIC.has(rel.slice(1))) return sendJson(res, 404, { error: 'Not found' });
    const file = path.join(publicDir, rel.slice(1));
    let entry = staticCache.get(file);
    if (!entry) {
      try {
        const buf = fs.readFileSync(file);
        entry = { buf, type: MIME[path.extname(file)] || 'application/octet-stream', etag: '"' + sha256(buf).slice(0, 20) + '"' };
        staticCache.set(file, entry);
      } catch (_) {
        return sendJson(res, 404, { error: 'Not found' });
      }
    }
    if (req.headers['if-none-match'] === entry.etag) { res.writeHead(304, baseHeaders()); return res.end(); }
    res.writeHead(200, { ...baseHeaders(), 'Content-Type': entry.type, 'Content-Length': entry.buf.length, ETag: entry.etag, 'Cache-Control': 'no-cache' });
    res.end(req.method === 'HEAD' ? undefined : entry.buf);
  }

  /* ───────── dispatcher ───────── */

  async function handler(req, res) {
    const ip = clientIp(req);
    try {
      const url = new URL(req.url, 'http://x');
      const pathname = decodeURIComponent(url.pathname);

      if (pathname.startsWith('/i/')) {
        if (req.method !== 'POST') throw new HttpError(405, 'Use POST', 'method_not_allowed');
        return await ingest(req, res, pathname.slice(3), ip);
      }
      if (!pathname.startsWith('/api/')) {
        if (req.method !== 'GET' && req.method !== 'HEAD') throw new HttpError(405, 'Method not allowed', 'method_not_allowed');
        return serveStatic(req, res, pathname);
      }

      const route = routes.find((r) => r.method === req.method && r.re.test(pathname));
      if (!route) {
        if (routes.some((r) => r.re.test(pathname))) throw new HttpError(405, 'Method not allowed', 'method_not_allowed');
        throw new HttpError(404, 'Not found', 'not_found');
      }
      const ctx = {
        req, res, ip, query: Object.fromEntries(url.searchParams), params: route.re.exec(pathname).groups || {}, body: {},
        json: (status, obj) => { ctx.sent = true; sendJson(res, status, obj); },
      };

      if (req.method !== 'GET' && req.method !== 'HEAD') {
        // CSRF defence in depth: custom header (forces CORS preflight, which we never grant) + same-origin check.
        if (req.headers['x-requested-with'] !== 'relayops') throw new HttpError(403, 'Missing X-Requested-With header', 'csrf');
        const origin = req.headers.origin;
        if (origin && origin !== config.publicUrl && new URL(origin).host !== req.headers.host) throw new HttpError(403, 'Cross-origin request blocked', 'csrf');
      }

      if (route.auth === 'user') {
        const token = A.parseCookies(req.headers.cookie)[cookieName];
        const s = A.lookupSession(db, token);
        if (!s) throw new HttpError(401, 'Not signed in', 'unauthenticated');
        ctx.session = s;
        ctx.user = { id: s.user_id, name: s.name, email: s.email, role: s.role };
        ctx.agency = { id: s.agency_id, name: s.agency_name };
      }
      if (req.method !== 'GET' && req.method !== 'HEAD' && req.method !== 'DELETE') ctx.body = await readJson(req);
      else if (req.method === 'DELETE') await readBody(req, 1024).catch(() => {});

      const result = await route.handler(ctx);
      if (!ctx.sent && !res.writableEnded && result !== undefined) sendJson(res, 200, result);
    } catch (e) {
      if (res.writableEnded) return;
      if (e instanceof HttpError) {
        const extra = e.retryAfter ? { 'Retry-After': String(e.retryAfter) } : e.status === 413 ? { Connection: 'close' } : {};
        return sendJson(res, e.status, { error: e.message, code: e.code }, extra);
      }
      log.error('[http] unhandled', e);
      sendJson(res, 500, { error: 'Internal server error', code: 'server_error' });
    }
  }

  const server = http.createServer(handler);
  server.requestTimeout = 30000;
  server.headersTimeout = 15000;
  server.keepAliveTimeout = 5000;

  return {
    db, engine, server, config,
    async start() {
      await new Promise((r) => server.listen(config.port, config.host, r));
      engine.start();
      return server.address();
    },
    async stop() {
      Object.values(limiters).forEach((l) => l.stop());
      testLimiter.stop();
      await engine.stop();
      await new Promise((r) => { server.close(r); server.closeAllConnections?.(); });
      db.close();
    },
  };
}

module.exports = { createApp };
