import { loadConfig } from './config.js';
import { openDb } from './db.js';
import { applySchema, seed } from './seed.js';
import { createApp } from './app.js';
import { purge } from './purge.js';
import { hashPassword, passwordProblem } from './security.js';
const cfg = loadConfig();
const db = await openDb({ url: cfg.databaseUrl, memory: !cfg.databaseUrl });
if (!cfg.databaseUrl) console.warn('[warn] DATABASE_URL not set: using a temporary in-memory database (data is lost on exit).');
await applySchema(db); await seed(db);
// First start only: create the Owner from environment variables (no terminal needed). Remove OWNER_PASSWORD afterwards.
if (process.env.OWNER_USERNAME && process.env.OWNER_EMAIL && process.env.OWNER_PASSWORD && !(await db.one('SELECT 1 x FROM users WHERE is_owner'))) {
  const bad = passwordProblem(process.env.OWNER_PASSWORD, 12);
  if (bad) console.error('[owner] not created: ' + bad);
  else { await db.q('INSERT INTO users (username,display_name,email,password_hash,is_owner,email_verified) VALUES ($1,$1,$2,$3,true,true)', [process.env.OWNER_USERNAME, process.env.OWNER_EMAIL.toLowerCase(), await hashPassword(process.env.OWNER_PASSWORD)]); console.log(`[owner] Owner "${process.env.OWNER_USERNAME}" created. Log in, enable 2FA, then delete OWNER_PASSWORD from the host settings.`); }
}
const app = createApp(db, cfg);
const srv = app.listen(cfg.port, () => console.log(`TWINS GAMING forum API listening on :${cfg.port}`));
const settingFn = async k => { const r = await db.one('SELECT value FROM settings WHERE key=$1', [k]); return r?.value; };
const run = () => purge(db, settingFn).catch(e => console.error('purge failed', e.message)); run(); setInterval(run, 6 * 3600_000).unref();
for (const s of ['SIGINT', 'SIGTERM']) process.on(s, () => srv.close(() => db.close().then(() => process.exit(0))));
