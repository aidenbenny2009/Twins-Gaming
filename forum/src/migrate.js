import { openDb } from './db.js';
import { applySchema, seed } from './seed.js';
import { loadConfig } from './config.js';
if (import.meta.url === `file://${process.argv[1]}`) {
  const cfg = loadConfig();
  const db = await openDb({ url: cfg.databaseUrl });
  console.log((await applySchema(db)) ? 'Schema created.' : 'Schema already present.');
  await seed(db); console.log('Seed data ensured.'); await db.close();
}
