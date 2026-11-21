// Apply pending migrations against DATABASE_URL (or the configured embedded database).
import { loadConfig } from './config.mjs';
import { createDb, migrate } from './db.mjs';
const db = await createDb(loadConfig());
await migrate(db);
console.log('migrations applied');
await db.close();
