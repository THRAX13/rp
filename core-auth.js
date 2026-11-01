'use strict';
const crypto = require('crypto');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);
const { sha256, now } = require('./core-util');

const PARAMS = { N: 32768, r: 8, p: 1, maxmem: 128 * 1024 * 1024 };

async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const dk = await scrypt(pw, salt, 64, PARAMS);
  return `scrypt$${PARAMS.N}$${PARAMS.r}$${PARAMS.p}$${salt.toString('base64')}$${dk.toString('base64')}`;
}

async function verifyPassword(pw, stored) {
  try {
    const [alg, N, r, p, salt, hash] = String(stored).split('$');
    if (alg !== 'scrypt') return false;
    const expected = Buffer.from(hash, 'base64');
    const dk = await scrypt(pw, Buffer.from(salt, 'base64'), expected.length, { N: +N, r: +r, p: +p, maxmem: PARAMS.maxmem });
    return crypto.timingSafeEqual(dk, expected);
  } catch (_) {
    return false;
  }
}

let dummyHash;
/** Burn equivalent CPU time when the user doesn't exist, to blunt account enumeration by timing. */
async function dummyVerify(pw) {
  dummyHash = dummyHash || (await hashPassword('dummy-password-for-timing'));
  await verifyPassword(pw, dummyHash);
}

function checkPasswordPolicy(pw) {
  if (typeof pw !== 'string' || pw.length < 10) return 'Password must be at least 10 characters';
  if (pw.length > 200) return 'Password is too long';
  if (/^(.)\1+$/.test(pw)) return 'Password is too simple';
  return null;
}

function parseCookies(header) {
  const out = {};
  String(header || '').split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}

function createSession(db, user, { ip, ua, days }) {
  const token = crypto.randomBytes(32).toString('base64url');
  const t = now();
  db.prepare('INSERT INTO sessions(token_hash,user_id,agency_id,created_at,expires_at,ip,ua) VALUES(?,?,?,?,?,?,?)')
    .run(sha256(token), user.id, user.agency_id, t, t + days * 86400000, ip || null, String(ua || '').slice(0, 200));
  return { token, expiresAt: t + days * 86400000 };
}

function lookupSession(db, token) {
  if (!token || token.length > 100) return null;
  const row = db.prepare(
    `SELECT s.token_hash, u.id AS user_id, u.agency_id, u.email, u.name, u.role, a.name AS agency_name
       FROM sessions s JOIN users u ON u.id=s.user_id JOIN agencies a ON a.id=u.agency_id
      WHERE s.token_hash=? AND s.expires_at>?`
  ).get(sha256(token), now());
  return row || null;
}

module.exports = { hashPassword, verifyPassword, dummyVerify, checkPasswordPolicy, parseCookies, createSession, lookupSession };
