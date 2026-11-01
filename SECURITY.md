# RelayOps security notes

## What v1.0 implements
- **Tenant isolation:** every API query is scoped by the signed-in user's workspace (`agency_id`); the browser never supplies it. Covered by tests (`e2e.test.js`).
- **Authentication:** scrypt (N=32768) password hashes, constant-time compare, dummy hashing for unknown users, 10-char minimum, per-IP and per-account sign-in rate limits, server-side sessions (random 256-bit token, only its SHA-256 stored), `HttpOnly; SameSite=Strict` cookie (`__Host-` prefix + `Secure` over https), password change revokes other sessions.
- **CSRF:** all state-changing requests require `X-Requested-With: relayops` (forces a CORS preflight that is never granted) plus an Origin check.
- **Ingest URLs:** 256-bit random tokens, stored only as SHA-256; shown once; rotatable. Optional/enforceable HMAC-SHA256 signatures with 5-minute timestamp tolerance and replay rejection; idempotency keys; per-URL, per-IP and bad-token rate limits; 256 KB body cap.
- **Outbound delivery (SSRF):** HTTPS only; no credentials in URLs; literal private/loopback/link-local/reserved/multicast/CGNAT/metadata addresses (IPv4, IPv6, IPv4-mapped, NAT64, 6to4) rejected at configuration time **and again at connect time** via a validating DNS lookup (defeats DNS rebinding — the connection uses the address that was validated); redirects are never followed; 10 s total timeout; 16 KB response cap.
- **Secrets at rest:** signing secrets encrypted with AES-256-GCM (key in `data/secret.key`, mode 0600, or `RELAYOPS_SECRET_KEY`). Lead payloads are deleted as soon as delivery succeeds; undelivered ones after 7 days. The UI never displays payload contents.
- **Web hardening:** strict CSP (`script-src 'self'`, no inline script/style), `X-Frame-Options: DENY`, `nosniff`, no-referrer, HSTS when `PUBLIC_URL` is https; all API responses `no-store`; CSV export neutralises spreadsheet formula injection; all SQL is parameterised.
- **Audit log** of sign-ins, destination changes, token/secret rotations, exports and team changes (owners can view the latest 100).

## Operator checklist before real customer data
1. Serve over **HTTPS** (reverse proxy) and set `PUBLIC_URL=https://…`, `TRUST_PROXY=1`.
2. Keep `ALLOW_PRIVATE_TARGETS` and `ALLOW_HTTP_TARGETS` **off**.
3. Keep `ALLOW_SIGNUP=0` unless you run RelayOps as a multi-agency service.
4. Run as a non-root user; restrict `data/` to that user; back it up (including `secret.key`).
5. Require signatures on destinations whose ingest URL might be exposed in client-side code.
6. Point scheduled checks at a test/health endpoint when the CRM would create junk leads.

## Not included (known gaps)
MFA/SSO, email-based invites and password reset (owners create accounts and set temporary passwords), distributed rate limiting, an external security review/pen-test. Lead data is personal data — check your own obligations (GDPR/DPDP etc.) and your client contracts before processing it.

## Reporting
Found a vulnerability? Tell the project owner privately rather than opening a public issue.
