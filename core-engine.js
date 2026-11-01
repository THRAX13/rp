'use strict';
const { newId, sha256, now } = require('./core-util');
const { tx, audit } = require('./core-db');
const { send, sign, decrypt } = require('./core-security');

const SYNTHETIC_PAYLOAD = (id) =>
  JSON.stringify({
    type: 'relayops.synthetic_test',
    id,
    sent_at: new Date().toISOString(),
    message: 'Synthetic delivery check from RelayOps Delivery Watch. Safe to discard.',
  });

/**
 * Delivery engine: queue, bounded retries with exponential backoff + jitter, dead-lettering,
 * scheduled synthetic checks, incident lifecycle, alerting and retention.
 */
class Engine {
  constructor({ db, config, log = console }) {
    this.db = db;
    this.cfg = config;
    this.log = log;
    this.inflight = new Set();
    this.timer = null;
    this.lastSchedule = 0;
    this.lastMaintenance = 0;
    this.stopped = false;
  }

  start() {
    this.stopped = false;
    this.timer = setInterval(() => this.tick().catch((e) => this.log.error('[engine] tick failed', e)), this.cfg.workerIntervalMs);
    this.timer.unref();
  }

  async stop() {
    this.stopped = true;
    clearInterval(this.timer);
    const deadline = Date.now() + 5000;
    while (this.inflight.size && Date.now() < deadline) await new Promise((r) => setTimeout(r, 50));
  }

  async tick() {
    if (this.stopped) return;
    const t = now();
    if (t - this.lastSchedule > 5000) { this.lastSchedule = t; this.scheduleChecks(t); }
    if (t - this.lastMaintenance > 3600000) { this.lastMaintenance = t; this.maintenance(t); }
    const room = this.cfg.maxConcurrentDeliveries - this.inflight.size;
    if (room <= 0) return;
    const due = this.db.prepare("SELECT id FROM deliveries WHERE status='queued' AND next_attempt_at<=? ORDER BY next_attempt_at LIMIT ?").all(t, room + 5);
    for (const d of due) if (this.inflight.size < this.cfg.maxConcurrentDeliveries) this.run(d.id);
  }

  /* ───── queueing ───── */

  enqueue({ dest, kind = 'lead', payload, contentType, idempotencyKey = null, sourceIp = null, runAt = null }) {
    const id = newId('evt_');
    const t = now();
    const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload || '');
    this.db.prepare(
      `INSERT INTO deliveries(id,agency_id,destination_id,kind,idempotency_key,status,attempts,max_attempts,next_attempt_at,
         payload,content_type,payload_bytes,payload_sha256,source_ip,created_at)
       VALUES(?,?,?,?,?,'queued',0,?,?,?,?,?,?,?,?)`
    ).run(id, dest.agency_id, dest.id, kind, idempotencyKey, kind === 'synthetic' ? 1 : this.cfg.maxAttempts,
      runAt === null ? t : runAt, body, contentType || 'application/octet-stream', body.length, sha256(body), sourceIp, t);
    return id;
  }

  /** Create + immediately execute a real synthetic check, returning the finished delivery row. */
  async checkNow(dest) {
    const id = newId('evt_');
    const payload = Buffer.from(SYNTHETIC_PAYLOAD(id));
    const evt = this.enqueue({ dest, kind: 'synthetic', payload, contentType: 'application/json', runAt: now() + 3600000 });
    await this.run(evt);
    return this.db.prepare('SELECT * FROM deliveries WHERE id=?').get(evt);
  }

  kick(id) {
    setImmediate(() => this.run(id));
  }

  scheduleChecks(t) {
    const due = this.db.prepare(
      'SELECT * FROM destinations WHERE check_interval_min>0 AND paused=0 AND (next_check_at IS NULL OR next_check_at<=?) LIMIT 100'
    ).all(t);
    for (const dest of due) {
      this.db.prepare('UPDATE destinations SET next_check_at=? WHERE id=?').run(t + dest.check_interval_min * 60000, dest.id);
      const id = newId('evt_');
      this.enqueue({ dest, kind: 'synthetic', payload: Buffer.from(SYNTHETIC_PAYLOAD(id)), contentType: 'application/json' });
    }
  }

  maintenance(t) {
    try {
      this.db.prepare('DELETE FROM sessions WHERE expires_at<?').run(t);
      const cutoff = t - this.cfg.retentionDays * 86400000;
      this.db.prepare("DELETE FROM deliveries WHERE status!='queued' AND created_at<?").run(cutoff);
      this.db.prepare('DELETE FROM audit WHERE created_at<?').run(t - 365 * 86400000);
      this.db.prepare("UPDATE deliveries SET payload=NULL WHERE payload IS NOT NULL AND status!='queued' AND completed_at<?")
        .run(t - this.cfg.payloadRetentionDays * 86400000);
    } catch (e) {
      this.log.error('[engine] maintenance failed', e);
    }
  }

  /* ───── execution ───── */

  async run(id) {
    if (this.inflight.has(id)) return;
    this.inflight.add(id);
    try {
      await this.attempt(id);
    } catch (e) {
      this.log.error('[engine] attempt failed', e);
    } finally {
      this.inflight.delete(id);
    }
  }

  backoffMs(n) {
    const base = Math.min(this.cfg.backoffCapSec, this.cfg.backoffBaseSec * 2 ** (n - 1));
    return Math.round(base * (0.8 + Math.random() * 0.4) * 1000); // ±20% jitter
  }

  classify(r) {
    if (r.errorKind) {
      if (r.errorKind === 'blocked') return { result: 'failed', retry: false, message: r.error };
      if (['dns', 'refused', 'tls'].includes(r.errorKind)) return { result: 'failed', retry: true, message: r.error };
      return { result: 'unconfirmed', retry: true, message: r.error };
    }
    const s = r.status;
    if (s >= 200 && s < 300) return { result: 'success', retry: false, message: null };
    if (s >= 300 && s < 400) return { result: 'failed', retry: false, message: `HTTP ${s} redirect not followed — update the destination URL${r.location ? ' to ' + r.location.slice(0, 120) : ''}` };
    if (s === 408 || s === 425 || s === 429 || s >= 500) return { result: 'failed', retry: true, message: `Destination returned HTTP ${s}` };
    return { result: 'failed', retry: false, message: `Destination rejected the request with HTTP ${s}` };
  }

  async attempt(id) {
    const d = this.db.prepare('SELECT * FROM deliveries WHERE id=?').get(id);
    if (!d || d.status !== 'queued') return;
    const dest = this.db.prepare('SELECT * FROM destinations WHERE id=?').get(d.destination_id);
    if (!dest) return;
    const n = d.attempts + 1;
    const body = d.payload ? Buffer.from(d.payload) : Buffer.alloc(0);
    const headers = {
      'Content-Type': d.content_type || 'application/octet-stream',
      'User-Agent': `RelayOps-DeliveryWatch/${this.cfg.version}`,
      'X-RelayOps-Event-Id': d.id,
      'X-RelayOps-Attempt': String(n),
      'X-RelayOps-Kind': d.kind,
    };
    if (d.kind === 'synthetic') headers['X-RelayOps-Synthetic'] = 'true';
    if (dest.outbound_secret_enc) {
      try {
        const ts = Math.floor(Date.now() / 1000);
        headers['X-RelayOps-Signature'] = `t=${ts},v1=${sign(decrypt(this.cfg.secretKey, dest.outbound_secret_enc), ts, body)}`;
      } catch (e) {
        this.log.error('[engine] cannot decrypt outbound secret', dest.id);
      }
    }
    const target = d.kind === 'synthetic' && dest.check_url ? dest.check_url : dest.url;
    const r = await send({
      url: target, body, headers,
      timeoutMs: this.cfg.deliveryTimeoutMs, maxResponseBytes: this.cfg.maxResponseBytes,
      allowHttp: this.cfg.allowHttpTargets, allowPrivate: this.cfg.allowPrivateTargets,
    });
    const out = this.classify(r);
    const t = now();
    const terminal = out.result === 'success' || !out.retry || n >= d.max_attempts;
    let consecutive = 0;

    tx(this.db, () => {
      this.db.prepare('INSERT INTO attempts(delivery_id,n,result,http_status,latency_ms,error,response_snippet,created_at) VALUES(?,?,?,?,?,?,?,?)')
        .run(id, n, out.result, r.status ?? null, r.latencyMs, out.message, r.snippet || null, t);
      if (terminal) {
        this.db.prepare(
          `UPDATE deliveries SET status=?,attempts=?,http_status=?,latency_ms=?,error=?,response_snippet=?,completed_at=?,next_attempt_at=NULL,
             payload=CASE WHEN ?='success' THEN NULL ELSE payload END WHERE id=?`
        ).run(out.result, n, r.status ?? null, r.latencyMs, out.message, r.snippet || null, t, out.result, id);
      } else {
        this.db.prepare('UPDATE deliveries SET attempts=?,http_status=?,latency_ms=?,error=?,response_snippet=?,next_attempt_at=? WHERE id=?')
          .run(n, r.status ?? null, r.latencyMs, out.message, r.snippet || null, t + this.backoffMs(n), id);
      }
      if (out.result === 'success') {
        this.db.prepare("UPDATE destinations SET status='healthy',consecutive_failures=0,last_checked_at=?,last_success_at=?,last_error=NULL WHERE id=?").run(t, t, dest.id);
      } else {
        this.db.prepare("UPDATE destinations SET status='attention',consecutive_failures=consecutive_failures+1,last_checked_at=?,last_error=? WHERE id=?").run(t, out.message, dest.id);
      }
      consecutive = this.db.prepare('SELECT consecutive_failures c FROM destinations WHERE id=?').get(dest.id)?.c || 0;
    });

    this.handleOutcome(dest, d, out, terminal, consecutive);
  }

  /* ───── incidents + alerts ───── */

  handleOutcome(dest, d, out, terminal, consecutive) {
    const open = this.db.prepare("SELECT * FROM incidents WHERE destination_id=? AND status='open'").get(dest.id);
    if (out.result === 'success') {
      if (open) {
        this.db.prepare("UPDATE incidents SET status='resolved',resolved_at=?,resolved_by='auto' WHERE id=?").run(now(), open.id);
        audit(this.db, dest.agency_id, null, 'incident.auto_resolved', `INC-${open.number} · ${dest.name}`);
        this.notify(dest.agency_id, 'incident.resolved', `✅ Resolved: ${dest.name} is delivering again (INC-${open.number}).`, { destination: dest.name, incident: open.number });
      }
      return;
    }
    const severity = out.result === 'failed' ? 'high' : 'medium';
    if (open) {
      this.db.prepare('UPDATE incidents SET failure_count=failure_count+1,detail=?,severity=CASE WHEN ?=\'high\' THEN \'high\' ELSE severity END WHERE id=?')
        .run(out.message, severity, open.id);
      return;
    }
    if (consecutive >= this.cfg.incidentThreshold || terminal) {
      const title = out.result === 'failed' ? `${dest.name} is rejecting deliveries` : `${dest.name} is not acknowledging deliveries`;
      let number;
      try {
        number = tx(this.db, () => {
          const num = this.db.prepare('SELECT COALESCE(MAX(number),0)+1 n FROM incidents WHERE agency_id=?').get(dest.agency_id).n;
          this.db.prepare('INSERT INTO incidents(id,agency_id,number,destination_id,delivery_id,severity,title,detail,failure_count,opened_at) VALUES(?,?,?,?,?,?,?,?,?,?)')
            .run(newId('inc_'), dest.agency_id, num, dest.id, d.id, severity, title, out.message, Math.max(1, consecutive), now());
          return num;
        });
      } catch (e) {
        return; // lost a race to another opener; the unique open-incident index protects us
      }
      audit(this.db, dest.agency_id, null, 'incident.opened', `INC-${number} · ${dest.name}`);
      this.notify(dest.agency_id, 'incident.opened', `🚨 Incident INC-${number}: ${title}. ${out.message || ''}`.trim(), { destination: dest.name, incident: number, severity });
    }
  }

  notify(agencyId, event, text, extra = {}) {
    const a = this.db.prepare('SELECT name,alert_webhook_url FROM agencies WHERE id=?').get(agencyId);
    if (!a || !a.alert_webhook_url) return Promise.resolve();
    return this.postAlert(a, { event, text, content: text, workspace: a.name, dashboard: this.cfg.publicUrl + '/#/incidents', ...extra });
  }

  async postAlert(agency, payload) {
    const r = await send({
      url: agency.alert_webhook_url,
      body: Buffer.from(JSON.stringify(payload)),
      headers: { 'Content-Type': 'application/json', 'User-Agent': `RelayOps-DeliveryWatch/${this.cfg.version}` },
      timeoutMs: 8000, allowHttp: this.cfg.allowHttpTargets, allowPrivate: this.cfg.allowPrivateTargets,
    });
    const ok = r.status >= 200 && r.status < 300;
    if (!ok) this.log.error(`[alerts] webhook failed for "${agency.name}": ${r.error || 'HTTP ' + r.status}`);
    return { ok, status: r.status, error: r.error || (ok ? null : `HTTP ${r.status}`) };
  }
}

module.exports = { Engine };
