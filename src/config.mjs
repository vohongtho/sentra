// Central configuration. Values come from environment variables only; never from the browser.
const bool = (v, d = false) => (v == null || v === '' ? d : ['1', 'true', 'yes', 'on'].includes(String(v).toLowerCase()));
const int = (v, d) => (v == null || v === '' || Number.isNaN(Number(v)) ? d : Number(v));

export function loadConfig(overrides = {}) {
  const e = { ...process.env, ...overrides };
  const environment = e.SENTRA_ENV || (e.NODE_ENV === 'production' ? 'production' : 'development');
  const port = int(e.PORT, 8080);
  const cfg = {
    environment,
    isProduction: environment === 'production',
    port,
    appOrigin: (e.APP_ORIGIN || `http://localhost:${port}`).replace(/\/$/, ''),
    // DATABASE_URL, or the standard libpq variables (PGHOST, PGUSER, PGDATABASE, PGPORT and the password variable),
    // so credentials need not be embedded in a URL.
    databaseUrl: e.DATABASE_URL || (e.PGHOST ? 'pg-env' : ''),
    pgliteDir: e.PGLITE_DIR || '', // empty => in-memory
    authMode: e.AUTH_MODE || 'keycloak', // keycloak | dev
    keycloak: {
      issuer: (e.KEYCLOAK_ISSUER || '').replace(/\/$/, ''),
      // Browser-facing issuer when the server reaches Keycloak by an internal hostname (docker compose).
      publicIssuer: (e.KEYCLOAK_PUBLIC_ISSUER || e.KEYCLOAK_ISSUER || '').replace(/\/$/, ''),
      clientId: e.KEYCLOAK_CLIENT_ID || '',
      clientSecret: e.KEYCLOAK_CLIENT_SECRET || '',
      allowHttpIssuer: bool(e.KEYCLOAK_ALLOW_HTTP, false), // local docker only; refused in production
      orgSlug: e.KEYCLOAK_DEFAULT_ORG || 'demo',
    },
    sessionTtlSeconds: int(e.SESSION_TTL_SECONDS, 8 * 3600),
    sessionIdleSeconds: int(e.SESSION_IDLE_SECONDS, 3600),
    masterKey: e.SENTRA_MASTER_KEY || '',
    objectStoreDir: e.OBJECT_STORE_DIR || '',
    s3: { bucket: e.S3_BUCKET || '', region: e.S3_REGION || 'auto', endpoint: e.S3_ENDPOINT || '' },
    runWorkers: bool(e.RUN_WORKERS, true),
    runScheduler: bool(e.RUN_SCHEDULER, true),
    workerPollMs: int(e.WORKER_POLL_MS, 1000),
    maxUploadBytes: int(e.MAX_UPLOAD_BYTES, 10 * 1024 * 1024),
    ai: {
      provider: e.AI_PROVIDER || (e.ANTHROPIC_API_KEY ? 'anthropic' : 'offline'),
      model: e.AI_MODEL || 'claude-opus-5-5',
      anthropicApiKey: e.ANTHROPIC_API_KEY || '',
      effort: e.AI_EFFORT || 'medium',
      baseUrl: e.ANTHROPIC_BASE_URL || undefined, // gateway/proxy or test double
    },
    smtp: { host: e.SMTP_HOST || '', port: int(e.SMTP_PORT, 587), secure: bool(e.SMTP_SECURE, false), user: e.SMTP_USER || '', pass: e.SMTP_PASS || '', from: e.SMTP_FROM || 'sentra@localhost' },
    allowPrivateWebhookTargets: bool(e.ALLOW_PRIVATE_WEBHOOK_TARGETS, false),
    githubWebhookSecret: e.GITHUB_WEBHOOK_SECRET || '',
    seedDemo: bool(e.SEED_DEMO, environment !== 'production'),
    rateLimitPerMinute: int(e.RATE_LIMIT_PER_MINUTE, 600),
    externalFeeds: bool(e.EXTERNAL_FEEDS, environment !== 'test'),
  };
  if (cfg.isProduction && cfg.authMode === 'dev') throw new Error('AUTH_MODE=dev is forbidden in production.');
  if (cfg.isProduction && !cfg.masterKey) throw new Error('SENTRA_MASTER_KEY is required in production.');
  if (cfg.isProduction && !cfg.databaseUrl) throw new Error('DATABASE_URL (PostgreSQL) is required in production.');
  if (cfg.isProduction && cfg.keycloak.allowHttpIssuer) throw new Error('KEYCLOAK_ALLOW_HTTP is forbidden in production.');
  return cfg;
}
