import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const PUBLIC = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../public');
export function loadConfig(env = process.env) {
  const prod = env.NODE_ENV === 'production';
  if (prod && (!env.SESSION_SECRET || env.SESSION_SECRET.length < 32)) throw new Error('SESSION_SECRET (32+ chars) is required in production');
  const publicUrl = (env.PUBLIC_URL || 'http://localhost:3000').replace(/\/$/, '');
  return {
    prod, googleClientId: env.GOOGLE_CLIENT_ID || '', port: +env.PORT || 3000, databaseUrl: env.DATABASE_URL || '', publicUrl,
    secret: env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
    origins: (env.ALLOWED_ORIGINS || publicUrl).split(',').map(s => s.trim()).filter(Boolean),
    trustProxy: env.TRUST_PROXY ? (isNaN(env.TRUST_PROXY) ? env.TRUST_PROXY : +env.TRUST_PROXY) : false,
    smtpUrl: env.SMTP_URL || '', mailFrom: env.MAIL_FROM || 'TWINS GAMING <no-reply@localhost>', siteName: env.SITE_NAME || 'TWINS GAMING',
    uploadDir: env.UPLOAD_DIR || './data/uploads', backupDir: env.BACKUP_DIR || './data/backups',
    turnstileSecret: env.TURNSTILE_SECRET || '', turnstileSite: env.TURNSTILE_SITE_KEY || '',
    staticDir: env.STATIC_DIR || (fs.existsSync(path.join(PUBLIC, 'index.html')) ? PUBLIC : ''), // optional: serve the front-end build from here
  };
}
