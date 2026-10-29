import crypto from 'node:crypto';
import { promisify } from 'node:util';
const scrypt = promisify(crypto.scrypt);

export async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const N = 16384, r = 8, p = 1;
  const h = await scrypt(pw, salt, 64, { N, r, p, maxmem: 64 * 1024 * 1024 });
  return `scrypt$${N}$${r}$${p}$${salt.toString('base64')}$${h.toString('base64')}`;
}
export async function verifyPassword(pw, stored) {
  try {
    const [alg, N, r, p, salt, hash] = stored.split('$');
    if (alg !== 'scrypt') return false;
    const h = await scrypt(pw, Buffer.from(salt, 'base64'), 64, { N: +N, r: +r, p: +p, maxmem: 64 * 1024 * 1024 });
    const want = Buffer.from(hash, 'base64');
    return want.length === h.length && crypto.timingSafeEqual(want, h);
  } catch { return false; }
}
export function passwordProblem(pw, minLen = 10) {
  if (typeof pw !== 'string' || pw.length < minLen) return `Password must be at least ${minLen} characters`;
  if (pw.length > 200) return 'Password is too long';
  if (!/[a-z]/i.test(pw) || !/[0-9]/.test(pw)) return 'Password must contain letters and numbers';
  return null;
}
export const token = (n = 32) => crypto.randomBytes(n).toString('base64url');
export const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');
export const hmac = (secret, s) => crypto.createHmac('sha256', secret).update(s).digest('base64url');
export const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };

// ---- TOTP (RFC 6238, SHA-1, 6 digits, 30 s) ----
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function b32encode(buf) { let bits = '', out = ''; for (const b of buf) bits += b.toString(2).padStart(8, '0'); for (let i = 0; i < bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5).padEnd(5, '0'), 2)]; return out; }
export function b32decode(s) { let bits = ''; for (const c of s.replace(/=+$/, '').toUpperCase()) { const v = B32.indexOf(c); if (v < 0) continue; bits += v.toString(2).padStart(5, '0'); } const out = []; for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2)); return Buffer.from(out); }
export const newTotpSecret = () => b32encode(crypto.randomBytes(20));
export function totpAt(secret, t = Date.now()) {
  const ctr = Buffer.alloc(8); ctr.writeBigUInt64BE(BigInt(Math.floor(t / 30000)));
  const h = crypto.createHmac('sha1', b32decode(secret)).update(ctr).digest();
  const o = h[19] & 15;
  return String(((h[o] & 0x7f) << 24 | h[o + 1] << 16 | h[o + 2] << 8 | h[o + 3]) % 1e6).padStart(6, '0');
}
export function totpVerify(secret, code, t = Date.now()) {
  code = String(code || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(code)) return false;
  return [-1, 0, 1].some(d => safeEq(totpAt(secret, t + d * 30000), code));
}
export const totpUri = (secret, label, issuer) => `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(label)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}`;

// ---- Self-hosted signed CAPTCHA (math), with optional Cloudflare Turnstile ----
const used = new Map();
export function makeCaptcha(secret) {
  const a = crypto.randomInt(2, 20), b = crypto.randomInt(2, 20), op = crypto.randomInt(0, 2) ? '+' : '-';
  const ans = op === '+' ? a + b : a - b, exp = Date.now() + 10 * 60 * 1000, nonce = token(8);
  const sig = hmac(secret, `${ans}|${exp}|${nonce}`);
  return { question: `What is ${a} ${op === '-' ? '−' : '+'} ${b}?`, token: `${exp}.${nonce}.${sig}` };
}
export function checkCaptcha(secret, tok, answer) {
  if (typeof tok !== 'string') return false;
  const [exp, nonce, sig] = tok.split('.');
  if (!exp || !nonce || !sig || Date.now() > +exp || used.has(nonce)) return false;
  if (!safeEq(hmac(secret, `${parseInt(answer, 10)}|${exp}|${nonce}`), sig)) return false;
  used.set(nonce, +exp);
  for (const [k, v] of used) if (v < Date.now()) used.delete(k);
  return true;
}
export async function verifyTurnstile(secretKey, response, ip) {
  try {
    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ secret: secretKey, response: response || '', remoteip: ip || '' }) });
    return !!(await r.json()).success;
  } catch { return false; }
}
// ---- image magic bytes ----
export function sniffImage(buf) {
  if (buf.length > 12 && buf[0] === 0x89 && buf.toString('latin1', 1, 4) === 'PNG') return { mime: 'image/png', ext: 'png' };
  if (buf.length > 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return { mime: 'image/jpeg', ext: 'jpg' };
  if (buf.length > 6 && buf.toString('latin1', 0, 3) === 'GIF') return { mime: 'image/gif', ext: 'gif' };
  if (buf.length > 12 && buf.toString('latin1', 0, 4) === 'RIFF' && buf.toString('latin1', 8, 12) === 'WEBP') return { mime: 'image/webp', ext: 'webp' };
  return null;
}
// ---- sealing small secrets (TOTP seeds) at rest with AES-256-GCM keyed from SESSION_SECRET ----
export function seal(secret, text) { const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', crypto.createHash('sha256').update(secret).digest(), iv); const e = Buffer.concat([c.update(text, 'utf8'), c.final()]); return [iv, c.getAuthTag(), e].map(b => b.toString('base64')).join('.'); }
export function unseal(secret, blob) { try { const [iv, tag, e] = blob.split('.').map(s => Buffer.from(s, 'base64')); const d = crypto.createDecipheriv('aes-256-gcm', crypto.createHash('sha256').update(secret).digest(), iv); d.setAuthTag(tag); return Buffer.concat([d.update(e), d.final()]).toString('utf8'); } catch { return null; } }
