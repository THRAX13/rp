'use strict';
const crypto = require('crypto');

const newId = (prefix = '') => prefix + crypto.randomBytes(12).toString('base64url');
const sha256 = (x) => crypto.createHash('sha256').update(x).digest('hex');
const now = () => Date.now();

class HttpError extends Error {
  constructor(status, message, code) {
    super(message);
    this.status = status;
    this.code = code || 'error';
  }
}

function str(v, { name = 'value', min = 0, max = 200, required = true } = {}) {
  if (v === undefined || v === null || v === '') {
    if (required) throw new HttpError(400, `${name} is required`, 'invalid_input');
    return '';
  }
  if (typeof v !== 'string') throw new HttpError(400, `${name} must be text`, 'invalid_input');
  const t = v.trim();
  if (t.length < min || t.length > max)
    throw new HttpError(400, `${name} must be ${min}–${max} characters`, 'invalid_input');
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(t)) throw new HttpError(400, `${name} contains invalid characters`, 'invalid_input');
  return t;
}

function csvCell(v) {
  let s = v === null || v === undefined ? '' : String(v);
  // Neutralise spreadsheet formula injection.
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  return '"' + s.replace(/"/g, '""') + '"';
}

module.exports = { newId, sha256, now, HttpError, str, csvCell };
