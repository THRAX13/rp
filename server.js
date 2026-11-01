#!/usr/bin/env node
'use strict';
const { fromEnv } = require('./core-config');
const { createApp } = require('./core-app');

const config = fromEnv();
const app = createApp(config);

app.start().then((addr) => {
  console.log(`\n  RelayOps Delivery Watch v${config.version}`);
  console.log(`  Listening on http://${addr.address}:${addr.port}`);
  console.log(`  Public URL (used in ingest links): ${config.publicUrl}`);
  console.log(`  Data directory: ${config.dataDir}\n`);
  if (config.allowPrivateTargets || config.allowHttpTargets)
    console.warn('  ⚠  DEV MODE: SSRF protections are relaxed (ALLOW_PRIVATE_TARGETS / ALLOW_HTTP_TARGETS). Do not expose this server publicly.\n');
  if (!config.publicUrl.startsWith('https://') && !/localhost|127\.0\.0\.1/.test(config.publicUrl))
    console.warn('  ⚠  PUBLIC_URL is not https — put RelayOps behind HTTPS before sending real leads through it.\n');
});

let closing = false;
async function shutdown(sig) {
  if (closing) return;
  closing = true;
  console.log(`\n${sig} received — shutting down…`);
  try { await app.stop(); } catch (e) { console.error(e); }
  process.exit(0);
}
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('unhandledRejection', (e) => console.error('[unhandledRejection]', e));
