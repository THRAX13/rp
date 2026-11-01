'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const http = require('http');
const S = require('./core-security');
const { csvCell } = require('./core-util');

test('isBlockedIp blocks private / reserved IPv4 and IPv6', () => {
  const blocked = ['127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0',
    '224.0.0.1', '255.255.255.255', '198.18.0.5', '::1', '::', 'fe80::1', 'fc00::1', 'fd12:3456::1', '::ffff:127.0.0.1', '::ffff:7f00:1',
    '::ffff:169.254.169.254', '64:ff9b::7f00:1', '2002:7f00:1::1', '2001:db8::1', 'ff02::1', 'fec0::1'];
  for (const ip of blocked) assert.equal(S.isBlockedIp(ip), true, ip);
  const allowed = ['8.8.8.8', '1.1.1.1', '93.184.216.34', '172.32.0.1', '2606:4700:4700::1111', '2a00:1450:4001::200e', '::ffff:8.8.8.8'];
  for (const ip of allowed) assert.equal(S.isBlockedIp(ip), false, ip);
});

test('validateTargetUrl rejects dangerous URLs', () => {
  const bad = ['http://example.com/x', 'ftp://example.com', 'https://user:pw@example.com', 'https://localhost/x', 'https://foo.internal/x',
    'https://127.0.0.1/x', 'https://[::1]/x', 'https://2130706433/x', 'https://0x7f.0.0.1/x', 'https://169.254.169.254/latest/meta-data', 'not a url', 'https://printer.local'];
  for (const u of bad) assert.equal(S.validateTargetUrl(u).ok, false, u);
  assert.equal(S.validateTargetUrl('https://hooks.example.com/a?b=1').ok, true);
  assert.equal(S.validateTargetUrl('http://127.0.0.1:9/x', { allowHttp: true, allowPrivate: true }).ok, true);
});

test('send() refuses private targets and cannot be redirected into them', async () => {
  const r = await S.send({ url: 'https://127.0.0.1/', body: Buffer.from('x') });
  assert.equal(r.errorKind, 'blocked');
  // A public-looking hostname that resolves to loopback (localhost via DNS) is blocked at connect time too.
  const r2 = await S.send({ url: 'https://localtest.me/', body: Buffer.from('x'), timeoutMs: 3000 });
  assert.ok(['blocked', 'dns', 'timeout', 'network'].includes(r2.errorKind), JSON.stringify(r2));
  assert.notEqual(r2.status, 200);
});

test('send() does not follow redirects and caps response size', async () => {
  let hits = 0;
  const srv = http.createServer((req, res) => {
    hits++;
    if (req.url === '/redir') { res.writeHead(302, { Location: 'http://127.0.0.1:1/secret' }); return res.end(); }
    res.writeHead(200); res.end('x'.repeat(5_000_000));
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${srv.address().port}`;
  const opts = { allowHttp: true, allowPrivate: true, body: Buffer.from('{}') };
  const a = await S.send({ ...opts, url: base + '/redir' });
  assert.equal(a.status, 302);
  assert.equal(hits, 1);
  const b = await S.send({ ...opts, url: base + '/big', maxResponseBytes: 1000 });
  assert.equal(b.status, 200);
  assert.ok(b.snippet.length <= 300);
  srv.closeAllConnections?.(); srv.close();
});

test('send() enforces a total timeout', async () => {
  const srv = http.createServer(() => { /* never respond */ });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const r = await S.send({ url: `http://127.0.0.1:${srv.address().port}/`, allowHttp: true, allowPrivate: true, timeoutMs: 300, body: Buffer.from('x') });
  assert.equal(r.errorKind, 'timeout');
  srv.closeAllConnections?.(); srv.close();
});

test('HMAC signature verification', () => {
  const secret = 'whsec_test'; const body = Buffer.from('{"a":1}'); const t = Math.floor(Date.now() / 1000);
  const hdr = `t=${t},v1=${S.sign(secret, t, body)}`;
  assert.equal(S.verifySignature(hdr, body, secret).ok, true);
  assert.equal(S.verifySignature(hdr, Buffer.from('{"a":2}'), secret).reason, 'bad_signature');
  assert.equal(S.verifySignature(hdr, body, 'other').reason, 'bad_signature');
  assert.equal(S.verifySignature(`t=${t - 1000},v1=${S.sign(secret, t - 1000, body)}`, body, secret).reason, 'timestamp_out_of_tolerance');
  assert.equal(S.verifySignature('garbage', body, secret).ok, false);
  assert.equal(S.verifySignature(undefined, body, secret).reason, 'missing_signature');
  assert.equal(S.verifySignature(`t=${t},v1=zz`, body, secret).ok, false);
});

test('secrets round-trip and tamper is detected', () => {
  const key = crypto.randomBytes(32);
  const enc = S.encrypt(key, 'whsec_abc');
  assert.equal(S.decrypt(key, enc), 'whsec_abc');
  assert.throws(() => S.decrypt(crypto.randomBytes(32), enc));
  const parts = enc.split('.'); parts[3] = Buffer.from('tampered').toString('base64url');
  assert.throws(() => S.decrypt(key, parts.join('.')));
});

test('CSV cells neutralise formula injection', () => {
  assert.equal(csvCell('=HYPERLINK("x")'), `"'=HYPERLINK(""x"")"`);
  assert.equal(csvCell('+1'), `"'+1"`);
  assert.equal(csvCell('normal'), '"normal"');
  assert.equal(csvCell(null), '""');
});
