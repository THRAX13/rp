'use strict';
const { DatabaseSync } = require('node:sqlite');

const SCHEMA = `
CREATE TABLE agencies(
  id TEXT PRIMARY KEY, name TEXT NOT NULL, alert_webhook_url TEXT, created_at INTEGER NOT NULL);
CREATE TABLE users(
  id TEXT PRIMARY KEY,
  agency_id TEXT NOT NULL REFERENCES agencies(id) ON DELETE CASCADE,
  email TEXT NOT NULL UNIQUE, name TEXT NOT NULL, password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('owner','member')),
  created_at INTEGER NOT NULL, last_login_at INTEGER);
CREATE INDEX idx_users_agency ON users(agency_id);
CREATE TABLE sessions(
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  agency_id TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, ip TEXT, ua TEXT);
CREATE INDEX idx_sessions_user ON sessions(user_id);
CREATE TABLE destinations(
  id TEXT PRIMARY KEY,
  agency_id TEXT NOT NULL REFERENCES agencies(id) ON DELETE CASCADE,
  name TEXT NOT NULL, url TEXT NOT NULL, check_url TEXT,
  token_hash TEXT NOT NULL UNIQUE, token_hint TEXT NOT NULL,
  inbound_secret_enc TEXT, require_signature INTEGER NOT NULL DEFAULT 0,
  outbound_secret_enc TEXT,
  check_interval_min INTEGER NOT NULL DEFAULT 0, next_check_at INTEGER,
  paused INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'unknown',
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  last_checked_at INTEGER, last_success_at INTEGER, last_error TEXT,
  created_at INTEGER NOT NULL);
CREATE INDEX idx_dest_agency ON destinations(agency_id);
CREATE TABLE deliveries(
  id TEXT PRIMARY KEY, agency_id TEXT NOT NULL,
  destination_id TEXT NOT NULL REFERENCES destinations(id) ON DELETE CASCADE,
  kind TEXT NOT NULL, idempotency_key TEXT,
  status TEXT NOT NULL DEFAULT 'queued',
  attempts INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL,
  next_attempt_at INTEGER,
  payload BLOB, content_type TEXT, payload_bytes INTEGER NOT NULL DEFAULT 0, payload_sha256 TEXT,
  http_status INTEGER, latency_ms INTEGER, error TEXT, response_snippet TEXT, source_ip TEXT,
  created_at INTEGER NOT NULL, completed_at INTEGER);
CREATE UNIQUE INDEX idx_deliv_idem ON deliveries(destination_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX idx_deliv_agency_time ON deliveries(agency_id, created_at DESC);
CREATE INDEX idx_deliv_due ON deliveries(status, next_attempt_at);
CREATE INDEX idx_deliv_dest ON deliveries(destination_id, status, created_at DESC);
CREATE TABLE attempts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  delivery_id TEXT NOT NULL REFERENCES deliveries(id) ON DELETE CASCADE,
  n INTEGER NOT NULL, result TEXT NOT NULL, http_status INTEGER, latency_ms INTEGER,
  error TEXT, response_snippet TEXT, created_at INTEGER NOT NULL);
CREATE INDEX idx_attempts_delivery ON attempts(delivery_id);
CREATE TABLE incidents(
  id TEXT PRIMARY KEY, agency_id TEXT NOT NULL REFERENCES agencies(id) ON DELETE CASCADE,
  number INTEGER NOT NULL,
  destination_id TEXT NOT NULL REFERENCES destinations(id) ON DELETE CASCADE,
  delivery_id TEXT, severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
  title TEXT NOT NULL, detail TEXT, failure_count INTEGER NOT NULL DEFAULT 1,
  opened_at INTEGER NOT NULL, resolved_at INTEGER, resolved_by TEXT,
  UNIQUE(agency_id, number));
CREATE UNIQUE INDEX idx_inc_open ON incidents(destination_id) WHERE status = 'open';
CREATE INDEX idx_inc_agency ON incidents(agency_id, opened_at DESC);
CREATE TABLE audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT, agency_id TEXT NOT NULL, user_id TEXT,
  action TEXT NOT NULL, detail TEXT, ip TEXT, created_at INTEGER NOT NULL);
CREATE INDEX idx_audit ON audit(agency_id, id DESC);
`;

const MIGRATIONS = [SCHEMA];

function open(file) {
  const db = new DatabaseSync(file);
  db.exec('PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA synchronous=NORMAL;');
  const cur = db.prepare('PRAGMA user_version').get().user_version;
  for (let v = cur; v < MIGRATIONS.length; v++) {
    db.exec('BEGIN');
    try {
      db.exec(MIGRATIONS[v]);
      db.exec(`PRAGMA user_version=${v + 1}`);
      db.exec('COMMIT');
    } catch (e) {
      db.exec('ROLLBACK');
      throw e;
    }
  }
  return db;
}

/** Run fn inside an IMMEDIATE transaction. */
function tx(db, fn) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const r = fn();
    db.exec('COMMIT');
    return r;
  } catch (e) {
    try { db.exec('ROLLBACK'); } catch (_) { /* ignore */ }
    throw e;
  }
}

function audit(db, agencyId, userId, action, detail, ip) {
  db.prepare('INSERT INTO audit(agency_id,user_id,action,detail,ip,created_at) VALUES(?,?,?,?,?,?)')
    .run(agencyId, userId || null, action, detail ? String(detail).slice(0, 500) : null, ip || null, Date.now());
}

module.exports = { open, tx, audit };
