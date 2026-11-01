# RelayOps — Delivery Watch v1.0.0

Monitors and protects lead delivery for agencies. Your lead sources (ad forms, website forms, Zapier…) POST to a private **RelayOps ingest URL**; RelayOps forwards each lead to the client's CRM/webhook, records the real HTTP acknowledgement, **retries failures**, **opens incidents** when a destination stops accepting leads, **alerts you**, and **closes the incident automatically** when it recovers.

This is a real, working application — no simulated data.

## Quick start (2 minutes)

Requires **Node.js 22.13 or newer** (no `npm install` needed — zero dependencies).

```bash
cd relayops
npm start
# → open http://localhost:3000 and create your workspace + owner account
```

Then:
1. **Destinations → Add destination** — enter the HTTPS URL where leads should land (your client's CRM / webhook).
2. Copy the **ingest URL** shown once, and point your lead source at it. (A ready-to-run `curl` example is shown too.)
3. Click **Test now** to send a real test event to the destination and see the acknowledgement.
4. Optionally set **Scheduled checks** (every 1 min – daily) and an **alert webhook** (Slack/Discord/any JSON endpoint) in Settings.

Run the tests with `npm test` (15 tests: SSRF guard, HMAC, retries, incidents, tenant isolation, auth…).

## How delivery works

| Step | Behaviour |
|---|---|
| Ingest | `POST /i/<token>` → validated, stored, answered `202 {id}` immediately |
| Forward | Raw body + content-type forwarded to the destination with `X-RelayOps-Event-Id`, `X-RelayOps-Attempt`, optional HMAC `X-RelayOps-Signature` |
| Success | Any `2xx` = acknowledged. Payload is erased from the database immediately |
| Retry | `408/425/429/5xx`, timeouts, connection errors: up to **5 attempts**, exponential backoff 30 s → 15 min with ±20 % jitter |
| No retry | Other `4xx` (the destination rejected the lead), `3xx` (redirects are never followed), blocked targets |
| Dead letter | After the last attempt the delivery is marked failed; payload is kept (7 days) so you can press **Retry delivery** |
| Incident | Opens after **2 consecutive failed attempts** or a terminal failure; severity *high* (rejected) or *medium* (no acknowledgement); **auto-resolves** on the next success |
| Alerts | JSON `POST` to your alert webhook on open and on recovery (`text` + `content` fields work with Slack and Discord) |

Delivery is **at-least-once**. If the server is killed mid-request, that lead is re-sent on restart. Destinations can de-duplicate on `X-RelayOps-Event-Id`. Senders can make ingest idempotent with an `Idempotency-Key` header.

## Sending leads

```bash
curl -X POST 'https://relayops.example.com/i/ro_…' \
  -H 'Content-Type: application/json' \
  -H 'Idempotency-Key: lead-12345' \
  -d '{"name":"Jane","email":"jane@example.com"}'
```

**Signed requests (recommended; enforceable per destination):**
`X-RelayOps-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256 of "<t>.<raw body>" using the signing secret>`
Timestamps older than 5 minutes are rejected; a signature can be used once (replay protection).

```js
// Node.js
const t = Math.floor(Date.now() / 1000);
const v1 = require('crypto').createHmac('sha256', SIGNING_SECRET).update(`${t}.${body}`).digest('hex');
headers['X-RelayOps-Signature'] = `t=${t},v1=${v1}`;
```
```python
# Python
t = int(time.time()); v1 = hmac.new(SECRET.encode(), f"{t}.{body}".encode(), hashlib.sha256).hexdigest()
```

Responses: `202` accepted · `200 {duplicate:true}` idempotent repeat · `401` bad/missing signature · `404` unknown URL · `409` paused or replayed · `413` > 256 KB · `429` rate-limited (120/min per URL).

If you set an **outbound signing secret** on a destination, forwarded requests carry the same `X-RelayOps-Signature` scheme so the destination can verify they came from RelayOps.

> **Scheduled checks and "Test now" send a real HTTP request** (`X-RelayOps-Synthetic: true`, JSON body `relayops.synthetic_test`) to the destination. If a CRM would turn that into a junk lead, set the destination's **Check URL** to a health/test endpoint.

## Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `PORT` / `HOST` | `3000` / `127.0.0.1` | Listen address (Docker uses `0.0.0.0`) |
| `PUBLIC_URL` | `http://localhost:PORT` | Base for ingest URLs. **Set to your real https URL in production** |
| `DATA_DIR` | `./data` | SQLite database + encryption key. **Back this folder up** |
| `ALLOW_SIGNUP` | `0` | Let others create their own workspaces from the sign-in page |
| `TRUST_PROXY` | `0` | Number of reverse proxies in front (reads client IP from `X-Forwarded-For`) |
| `RELAYOPS_SECRET_KEY` | auto (`data/secret.key`) | Derive the at-rest encryption key from this instead |
| `MAX_ATTEMPTS`, `BACKOFF_BASE_SEC`, `BACKOFF_CAP_SEC` | `5`, `30`, `900` | Retry policy |
| `INCIDENT_THRESHOLD` | `2` | Consecutive failures before an incident opens |
| `DELIVERY_TIMEOUT_MS` | `10000` | Per-attempt total timeout |
| `RETENTION_DAYS`, `PAYLOAD_RETENTION_DAYS` | `90`, `7` | Event history / undelivered payload retention |
| `ALLOW_PRIVATE_TARGETS`, `ALLOW_HTTP_TARGETS` | `0` | **Dev only** – disables SSRF protection |

See `env.example` (rename it to `.env` if your hosting tool wants one).

## Deploying

**Docker** (`docker compose up -d --build`): edit `PUBLIC_URL` in `docker-compose.yml`, and put a TLS reverse proxy in front (Caddy, nginx, Cloudflare Tunnel). The container runs as a non-root user and stores everything in the `/data` volume.

**Any VPS / Raspberry Pi / Railway / Fly.io / Render (with a persistent disk):** `node server.js` under systemd or pm2, behind HTTPS.

**Backups:** stop the app (or use `sqlite3 data/relayops.db ".backup backup.db"`) and copy `data/`. Keep `data/secret.key` with the database — without it the stored signing secrets can't be decrypted.

**Why not Vercel/Supabase?** The README of the demo suggested Next.js + Supabase + Vercel. RelayOps needs a long-running worker for retries and scheduled checks, which doesn't fit serverless functions, so v1.0 is a single self-contained process with SQLite. Moving to Postgres + a worker is a clean next step if you outgrow one server (the data model is plain SQL; all queries are in `core-app.js` and `core-engine.js`).

## Known limits (honest list)

- **Single process / single server.** Fine for hundreds of thousands of events a month; not horizontally scalable.
- Rate limits and the signature-replay cache are in memory (reset on restart; the 5-minute timestamp window and idempotency keys cover restarts).
- Alerts are via webhook only (Slack/Discord/etc.). No built-in email/SMS.
- No MFA or SSO; passwords are scrypt-hashed, sessions are HttpOnly/SameSite=Strict cookies, sign-in is rate-limited.
- Not independently penetration-tested. See `SECURITY.md` before sending real customer data through it.

## Files (flat layout, no folders)

Everything sits in one folder so it can be uploaded through GitHub's web page without folder support:
`server.js` (entry) · `core-*.js` (backend) · `index.html`, `ui.js`, `ui.css`, `favicon.svg` (web UI) · `*.test.js` (tests) · `package.json`, `Dockerfile`, `docker-compose.yml`, `env.example`, docs.
Only the four UI files are served to browsers; the backend source is never exposed.
When you create the repo, add a `.gitignore` containing one line, `data/`, so your database never gets committed.
