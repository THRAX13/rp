'use strict';
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

function loadSecretKey(dataDir, env) {
  if (env.RELAYOPS_SECRET_KEY) return crypto.createHash('sha256').update(String(env.RELAYOPS_SECRET_KEY)).digest();
  const f = path.join(dataDir, 'secret.key');
  if (fs.existsSync(f)) {
    const k = Buffer.from(fs.readFileSync(f, 'utf8').trim(), 'hex');
    if (k.length === 32) return k;
  }
  const k = crypto.randomBytes(32);
  fs.writeFileSync(f, k.toString('hex'), { mode: 0o600 });
  return k;
}

function fromEnv(env = process.env, overrides = {}) {
  const num = (k, d) => (env[k] !== undefined && env[k] !== '' && Number.isFinite(Number(env[k])) ? Number(env[k]) : d);
  const bool = (k, d = false) => (env[k] === undefined || env[k] === '' ? d : /^(1|true|yes|on)$/i.test(env[k]));
  const dataDir = path.resolve(env.DATA_DIR || path.join(__dirname, 'data'));
  fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const port = num('PORT', 3000);
  const publicUrl = String(env.PUBLIC_URL || `http://localhost:${port}`).replace(/\/+$/, '');
  const cfg = {
    version: require('./package.json').version,
    port,
    host: env.HOST || '127.0.0.1',
    dataDir,
    dbFile: path.join(dataDir, 'relayops.db'),
    publicUrl,
    secureCookies: bool('SECURE_COOKIES', publicUrl.startsWith('https://')),
    trustProxy: num('TRUST_PROXY', 0),
    allowSignup: bool('ALLOW_SIGNUP', false),
    allowHttpTargets: bool('ALLOW_HTTP_TARGETS', false),
    allowPrivateTargets: bool('ALLOW_PRIVATE_TARGETS', false),
    maxPayloadBytes: num('MAX_PAYLOAD_BYTES', 256 * 1024),
    ingestRatePerMin: num('INGEST_RATE_PER_MIN', 120),
    deliveryTimeoutMs: num('DELIVERY_TIMEOUT_MS', 10000),
    maxResponseBytes: 16 * 1024,
    maxAttempts: num('MAX_ATTEMPTS', 5),
    backoffBaseSec: num('BACKOFF_BASE_SEC', 30),
    backoffCapSec: num('BACKOFF_CAP_SEC', 900),
    incidentThreshold: num('INCIDENT_THRESHOLD', 2),
    maxConcurrentDeliveries: num('MAX_CONCURRENT_DELIVERIES', 10),
    retentionDays: num('RETENTION_DAYS', 90),
    payloadRetentionDays: num('PAYLOAD_RETENTION_DAYS', 7),
    sessionDays: num('SESSION_DAYS', 7),
    workerIntervalMs: 1000,
    quiet: false,
    ...overrides,
  };
  cfg.secretKey = overrides.secretKey || loadSecretKey(dataDir, env);
  return cfg;
}

module.exports = { fromEnv };
