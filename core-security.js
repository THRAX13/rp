'use strict';
const crypto = require('crypto');
const dns = require('dns');
const net = require('net');
const http = require('http');
const https = require('https');

/* ───────────── IP classification (SSRF guard) ───────────── */

function v4ToInt(ip) {
  const p = ip.split('.').map(Number);
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}
const V4_BLOCKS = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
].map(([b, l]) => ({ base: v4ToInt(b), mask: (~0 << (32 - l)) >>> 0 }));

function isBlockedV4(ip) {
  const n = v4ToInt(ip) >>> 0;
  return V4_BLOCKS.some((b) => ((n & b.mask) >>> 0) === ((b.base & b.mask) >>> 0));
}

function v6Bytes(ip) {
  let s = ip.split('%')[0].toLowerCase();
  const m = s.match(/(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (m) {
    const p = m.slice(1).map(Number);
    s = s.slice(0, s.length - m[0].length) + ((p[0] << 8) | p[1]).toString(16) + ':' + ((p[2] << 8) | p[3]).toString(16);
  }
  let groups;
  if (s.includes('::')) {
    const [head, tail] = s.split('::');
    const l = head ? head.split(':') : [];
    const r = tail ? tail.split(':') : [];
    groups = [...l, ...Array(8 - l.length - r.length).fill('0'), ...r];
  } else groups = s.split(':');
  if (groups.length !== 8) return null;
  const out = Buffer.alloc(16);
  groups.forEach((g, i) => out.writeUInt16BE(parseInt(g || '0', 16) & 0xffff, i * 2));
  return out;
}

function isBlockedV6(ip) {
  const b = v6Bytes(ip);
  if (!b) return true;
  const embedded = (o) => `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`;
  const first96Zero = b.subarray(0, 12).every((x) => x === 0);
  if (first96Zero) return true; // ::, ::1, IPv4-compatible
  if (b.subarray(0, 10).every((x) => x === 0) && b[10] === 0xff && b[11] === 0xff) return isBlockedV4(embedded(12)); // ::ffff:a.b.c.d
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b && b.subarray(4, 12).every((x) => x === 0)) return isBlockedV4(embedded(12)); // NAT64
  if (b[0] === 0x20 && b[1] === 0x02) return isBlockedV4(embedded(2)); // 6to4
  if ((b[0] & 0xe0) !== 0x20) return true; // not global unicast 2000::/3
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] < 0x02) return true; // 2001::/23 (teredo, protocol assignments)
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x0d && b[3] === 0xb8) return true; // documentation
  return false;
}

function isBlockedIp(ip) {
  if (net.isIPv4(ip)) return isBlockedV4(ip);
  if (net.isIPv6(ip)) return isBlockedV6(ip);
  return true;
}

/* ───────────── URL validation ───────────── */

function validateTargetUrl(input, opts = {}) {
  let u;
  try {
    if (typeof input !== 'string' || input.length > 2048) throw new Error('bad');
    u = new URL(input.trim());
  } catch (_) {
    return { ok: false, error: 'Enter a valid URL' };
  }
  const httpsOnly = !opts.allowHttp;
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && opts.allowHttp))
    return { ok: false, error: httpsOnly ? 'Only https:// URLs are allowed' : 'Only http(s) URLs are allowed' };
  if (u.username || u.password) return { ok: false, error: 'URLs with embedded credentials are not allowed' };
  const host = u.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
  if (!host) return { ok: false, error: 'URL has no host' };
  if (!opts.allowPrivate) {
    if (host === 'localhost' || /\.(localhost|local|internal|localdomain|home\.arpa)$/.test(host))
      return { ok: false, error: 'Local and internal hostnames are not allowed' };
    if (net.isIP(host) && isBlockedIp(host)) return { ok: false, error: 'Private, loopback and reserved IP addresses are not allowed' };
  }
  return { ok: true, url: u, host };
}

/** DNS lookup that refuses to resolve to private/reserved space — used for the actual connection, defeating DNS rebinding. */
function guardedLookup(hostname, options, cb) {
  if (typeof options === 'function') { cb = options; options = {}; }
  dns.lookup(hostname, { all: true, verbatim: true, family: options.family || 0 }, (err, addrs) => {
    if (err) return cb(err);
    if (!addrs.length || addrs.some((a) => isBlockedIp(a.address))) {
      const e = new Error('Target resolves to a private or reserved address');
      e.code = 'ERR_BLOCKED_TARGET';
      return cb(e);
    }
    if (options.all) return cb(null, addrs);
    cb(null, addrs[0].address, addrs[0].family);
  });
}

/* ───────────── Outbound request ───────────── */

/**
 * POST a body to a URL with SSRF protection, total timeout, response-size cap, no redirect following.
 * Never throws; resolves { status, snippet, latencyMs, error, errorKind }.
 */
function send({ url, body = Buffer.alloc(0), headers = {}, timeoutMs = 10000, maxResponseBytes = 16384, allowHttp = false, allowPrivate = false }) {
  return new Promise((resolve) => {
    const t0 = Date.now();
    let done = false;
    let timer;
    let req;
    const finish = (r) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      r.latencyMs = Date.now() - t0;
      resolve(r);
    };
    try {
      const v = validateTargetUrl(url, { allowHttp, allowPrivate });
      if (!v.ok) return finish({ status: null, error: 'Blocked: ' + v.error, errorKind: 'blocked' });
      const u = v.url;
      const lib = u.protocol === 'https:' ? https : http;
      req = lib.request(
        {
          protocol: u.protocol,
          hostname: u.hostname.replace(/^\[|\]$/g, ''),
          port: u.port || undefined,
          path: u.pathname + u.search,
          method: 'POST',
          agent: false,
          lookup: allowPrivate ? undefined : guardedLookup,
          headers: { ...headers, 'Content-Length': body.length, Connection: 'close' },
        },
        (res) => {
          const chunks = [];
          let size = 0;
          res.on('data', (c) => {
            if (size < maxResponseBytes) { chunks.push(c); size += c.length; }
            if (size >= maxResponseBytes) res.destroy();
          });
          const end = () => {
            const text = Buffer.concat(chunks).toString('utf8').replace(/[^\x20-\x7e\n\t]/g, '').slice(0, 300);
            finish({ status: res.statusCode, snippet: text, location: res.headers.location || null });
          };
          res.on('end', end);
          res.on('close', end);
          res.on('error', end);
        }
      );
      timer = setTimeout(() => {
        const e = new Error(`No response within ${Math.round(timeoutMs / 1000)}s`);
        e.code = 'ETIMEDOUT_TOTAL';
        req.destroy(e);
      }, timeoutMs);
      req.on('error', (e) => {
        const code = e.code || '';
        let kind = 'network';
        let msg = e.message;
        if (code === 'ERR_BLOCKED_TARGET') { kind = 'blocked'; msg = 'Blocked: ' + e.message; }
        else if (code === 'ETIMEDOUT_TOTAL' || code === 'ETIMEDOUT') { kind = 'timeout'; }
        else if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') { kind = 'dns'; msg = 'DNS lookup failed for destination host'; }
        else if (code === 'ECONNREFUSED') { kind = 'refused'; msg = 'Connection refused by destination'; }
        else if (/CERT|TLS|SSL|ERR_TLS|DEPTH_ZERO|SELF_SIGNED|UNABLE_TO_VERIFY/i.test(code + e.message)) { kind = 'tls'; msg = 'TLS error: ' + e.message; }
        finish({ status: null, error: msg.slice(0, 300), errorKind: kind });
      });
      req.end(body);
    } catch (e) {
      finish({ status: null, error: String(e.message || e).slice(0, 300), errorKind: 'network' });
    }
  });
}

/* ───────────── HMAC signatures ───────────── */

const sign = (secret, t, body) =>
  crypto.createHmac('sha256', secret).update(`${t}.`).update(body).digest('hex');

function verifySignature(header, body, secret, { toleranceSec = 300, now = Date.now() } = {}) {
  if (!header || typeof header !== 'string') return { ok: false, reason: 'missing_signature' };
  const parts = Object.fromEntries(header.split(',').map((p) => p.trim().split('=')).filter((p) => p.length === 2));
  const t = Number(parts.t);
  if (!Number.isFinite(t) || !parts.v1) return { ok: false, reason: 'malformed_signature' };
  if (Math.abs(now / 1000 - t) > toleranceSec) return { ok: false, reason: 'timestamp_out_of_tolerance' };
  const expected = Buffer.from(sign(secret, t, body), 'hex');
  let given;
  try { given = Buffer.from(parts.v1, 'hex'); } catch (_) { return { ok: false, reason: 'malformed_signature' }; }
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return { ok: false, reason: 'bad_signature' };
  return { ok: true, nonce: parts.v1 };
}

/* ───────────── Secrets at rest ───────────── */

function encrypt(key, plain) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  return ['v1', iv.toString('base64url'), c.getAuthTag().toString('base64url'), ct.toString('base64url')].join('.');
}
function decrypt(key, blob) {
  const [v, iv, tag, ct] = String(blob).split('.');
  if (v !== 'v1') throw new Error('bad ciphertext');
  const d = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64url'));
  d.setAuthTag(Buffer.from(tag, 'base64url'));
  return Buffer.concat([d.update(Buffer.from(ct, 'base64url')), d.final()]).toString('utf8');
}

const randomToken = (prefix, bytes = 32) => prefix + crypto.randomBytes(bytes).toString('base64url');

module.exports = { isBlockedIp, validateTargetUrl, guardedLookup, send, sign, verifySignature, encrypt, decrypt, randomToken };
