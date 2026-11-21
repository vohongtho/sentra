// Run Sentra against the local docker Keycloak realm (keycloak/sentra-realm.json) on http://localhost:8080.
// The client credential is read from the local development realm file; never use that realm outside a laptop.
import { readFile } from 'node:fs/promises';
import { createApp } from '../src/app.mjs';
const realm = JSON.parse(await readFile(new URL('../keycloak/sentra-realm.json', import.meta.url), 'utf8'));
const client = realm.clients.find(c => c.clientId === 'sentra');
const app = await createApp({
  SENTRA_ENV: 'development', PORT: '8080', APP_ORIGIN: 'http://localhost:8080', AUTH_MODE: 'keycloak',
  KEYCLOAK_ISSUER: 'http://localhost:8081/realms/sentra', KEYCLOAK_CLIENT_ID: 'sentra', KEYCLOAK_CLIENT_SECRET: client.secret, KEYCLOAK_ALLOW_HTTP: 'true',
  PGLITE_DIR: process.argv[2] || './data/pg-kc', OBJECT_STORE_DIR: './data/objects-kc', EXTERNAL_FEEDS: 'false',
});
await app.start();
