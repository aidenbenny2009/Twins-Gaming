// Usage: DATABASE_URL=... node scripts/create-owner.js <username> <email>   (password is prompted via OWNER_PASSWORD env or stdin)
import readline from 'node:readline';
import { loadConfig } from '../src/config.js';
import { openDb } from '../src/db.js';
import { applySchema, seed } from '../src/seed.js';
import { hashPassword, passwordProblem } from '../src/security.js';
const [username, email] = process.argv.slice(2);
if (!username || !email) { console.error('Usage: node scripts/create-owner.js <username> <email>'); process.exit(1); }
let pw = process.env.OWNER_PASSWORD;
if (!pw) { const rl = readline.createInterface({ input: process.stdin, output: process.stdout }); pw = await new Promise(r => rl.question('Owner password (min 12 chars): ', a => { rl.close(); r(a); })); }
const bad = passwordProblem(pw, 12); if (bad) { console.error(bad); process.exit(1); }
const db = await openDb({ url: loadConfig().databaseUrl });
await applySchema(db); await seed(db);
if (await db.one('SELECT 1 x FROM users WHERE is_owner')) { console.error('An Owner already exists. There can only be one.'); process.exit(1); }
await db.q('INSERT INTO users (username,display_name,email,password_hash,is_owner,email_verified) VALUES ($1,$1,$2,$3,true,true)', [username, email.toLowerCase(), await hashPassword(pw)]);
console.log(`Owner "${username}" created. Enable 2FA from the account page after logging in.`); await db.close();
