export class HttpError extends Error {
  constructor(status, message, extra) { super(message); this.status = status; this.extra = extra; }
}
export const bad = (m, x) => new HttpError(400, m, x);
export const forbid = (m = 'Permission denied') => new HttpError(403, m);
export const nf = (m = 'Not found') => new HttpError(404, m);
export const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
export function int(v, name = 'id') {
  const n = Number(v);
  if (!Number.isInteger(n) || n < 0 || n > 2147483647) throw bad(`Invalid ${name}`);
  return n;
}
export function str(v, name, { min = 1, max = 1000, optional = false } = {}) {
  if (v == null || v === '') { if (optional) return null; throw bad(`${name} is required`); }
  if (typeof v !== 'string') throw bad(`${name} must be text`);
  const s = v.trim();
  if (s.length < min) throw bad(`${name} is too short (min ${min})`);
  if (s.length > max) throw bad(`${name} is too long (max ${max})`);
  return s;
}
export function bool(v) { return v === true || v === 'true' || v === 1 || v === '1'; }
export function oneOf(v, list, name) { if (!list.includes(v)) throw bad(`${name} must be one of: ${list.join(', ')}`); return v; }
export function paging(req, def = 20, max = 100) {
  const limit = Math.min(Math.max(parseInt(req.query.limit) || def, 1), max);
  const page = Math.max(parseInt(req.query.page) || 1, 1);
  return { limit, page, offset: (page - 1) * limit };
}
export function safeUrl(u, name = 'url') {
  const s = str(u, name, { max: 2000 });
  if (s.startsWith('/')) return s;
  let x; try { x = new URL(s); } catch { throw bad(`${name} is not a valid URL`); }
  if (!['http:', 'https:', 'mailto:'].includes(x.protocol)) throw bad(`${name} must be http(s)`);
  return s;
}
export const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
export function csv(rows) {
  if (!rows.length) return '';
  const cols = Object.keys(rows[0]);
  const cell = v => { let s = v == null ? '' : v instanceof Date ? v.toISOString() : typeof v === 'object' ? JSON.stringify(v) : String(v); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
  return [cols.join(','), ...rows.map(r => cols.map(c => cell(r[c])).join(','))].join('\n');
}
