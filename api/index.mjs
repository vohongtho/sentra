// Vercel serverless entry (frontend + bounded API/BFF). Workers and the scheduler cannot run inside serverless
// functions: deploy `node src/server.mjs` with RUN_WORKERS=true RUN_SCHEDULER=true on a long-running host
// (container, VM) against the same PostgreSQL database. This adapter forces both off.
import { createApp } from '../src/app.mjs';

let ready;
function init() {
  ready ??= createApp({ RUN_WORKERS: 'false', RUN_SCHEDULER: 'false', SEED_DEMO: 'false' });
  return ready;
}
export default async function handler(req, res) {
  const app = await init();
  const u = new URL(req.url, 'http://local');
  const forwarded = u.searchParams.get('__path');
  if (forwarded) { u.searchParams.delete('__path'); req.url = forwarded + (u.search || ''); }
  app.server.emit('request', req, res);
}
export const config = { maxDuration: 60 };
