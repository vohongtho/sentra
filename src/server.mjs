#!/usr/bin/env node
import { createApp } from './app.mjs';
import { log } from './log.mjs';

const app = await createApp();
await app.start();
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, async () => { log.info('shutdown', { signal: sig }); await app.stop().catch(() => {}); process.exit(0); });
