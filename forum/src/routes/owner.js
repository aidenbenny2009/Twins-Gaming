import { Router } from 'express';
import fs from 'node:fs/promises';
import path from 'node:path';
import { wrap, bad, str, int, oneOf, paging, csv, forbid, nf, HttpError } from '../util.js';
import { PERMS, DEFAULT_SETTINGS, BASE, MOD } from '../seed.js';
const DEFAULT_MEMBER_PERMS = BASE, DEFAULT_STAFF_PERMS = MOD;
import { purge } from '../purge.js';

const EXPORTS = { users: 'id,username,display_name,email,email_verified,status,banned_until,reg_ip,last_ip,created_at,last_login_at', audit_logs: '*', security_logs: '*', login_attempts: '*', threads: '*', posts: 'id,thread_id,author_id,created_at,deleted_at,left(body,2000) AS body', reports: '*', sanctions: '*' };

export default function (ctx) {
  const r = Router(), { db, cfg } = ctx, can = ctx.can;
  const M = ctx.need('MANAGE_USERS');

  // ---------- users ----------
  r.get('/admin/users', M, wrap(async (req, res) => {
    const { limit, offset } = paging(req, 30, 200), q = String(req.query.q || '').replace(/[%_\\]/g, '\\$&'), ip = can(req.user, 'VIEW_IP');
    const rows = await db.q(`SELECT u.id,u.username,u.display_name,u.email,u.status,u.is_owner,u.email_verified,u.banned_until,u.muted_until,u.totp_enabled,u.created_at,u.last_login_at,u.last_active_at,${ip ? 'u.reg_ip,u.last_ip' : 'NULL::text AS reg_ip,NULL::text AS last_ip'},
      COALESCE((SELECT json_agg(r.name) FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=u.id),'[]') AS roles FROM users u
      WHERE ($1='' OR u.username ILIKE '%'||$1||'%' OR u.email ILIKE '%'||$1||'%') ORDER BY u.id DESC LIMIT ${limit} OFFSET ${offset}`, [q]);
    res.json(rows);
  }));
  async function target(req, { allowStaff = false } = {}) {
    const u = await db.one('SELECT * FROM users WHERE id=$1', [int(req.params.id)]); if (!u) throw nf('User not found');
    if (u.is_owner && !req.user.is_owner) throw forbid('The Owner account cannot be modified');
    if (u.id === req.user.id && !allowStaff) throw bad('You cannot do that to your own account');
    if (!req.user.is_owner && !allowStaff) { const staff = await db.one('SELECT 1 x FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=$1 AND r.is_staff', [u.id]); if (staff) throw forbid('Only the Owner can act on staff accounts'); }
    return u;
  }
  r.get('/admin/users/:id', M, wrap(async (req, res) => {
    const u = await target(req, { allowStaff: true }), id = u.id;
    const extra = { sanctions: await db.q('SELECT s.*, st.username AS staff FROM sanctions s LEFT JOIN users st ON st.id=s.staff_id WHERE s.user_id=$1 ORDER BY s.id DESC', [id]), sessions: await db.q('SELECT id,ip,ua,created_at,last_active_at,revoked_at FROM sessions WHERE user_id=$1 ORDER BY id DESC LIMIT 20', [id]), security: await db.q('SELECT event,ip,created_at FROM security_logs WHERE user_id=$1 ORDER BY id DESC LIMIT 50', [id]), roles: await db.q('SELECT r.id,r.name FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=$1', [id]) };
    const { password_hash, totp_secret, prefs, ...safe } = u; if (!can(req.user, 'VIEW_IP')) { delete safe.reg_ip; delete safe.last_ip; extra.sessions.forEach(s => delete s.ip); extra.security.forEach(s => delete s.ip); }
    res.json({ ...safe, ...extra });
  }));
  r.patch('/admin/users/:id', M, wrap(async (req, res) => {
    const u = await target(req), b = req.body, sets = [], args = [u.id];
    if (b.display_name != null) { args.push(str(b.display_name, 'Display name', { min: 2, max: 32 })); sets.push(`display_name=$${args.length}`); }
    if (b.email != null) { args.push(str(b.email, 'Email', { max: 254 }).toLowerCase()); sets.push(`email=$${args.length}`); }
    if (b.force_reset != null) { args.push(!!b.force_reset); sets.push(`force_reset=$${args.length}`); }
    if (b.email_verified != null) { args.push(!!b.email_verified); sets.push(`email_verified=$${args.length}`); }
    if (b.status != null) { args.push(oneOf(b.status, ['active', 'disabled'], 'status')); sets.push(`status=$${args.length}`); }
    if (!sets.length) return res.json({ ok: true });
    await db.q(`UPDATE users SET ${sets.join(',')} WHERE id=$1`, args);
    if (b.status === 'disabled') await db.q('UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL', [u.id]);
    await ctx.audit(req, 'user_update', 'user', u.id, null, { ...b, password: undefined }, b.reason); res.json({ ok: true });
  }));
  r.post('/admin/users/:id/force-logout', M, wrap(async (req, res) => { const u = await target(req); await db.q('UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL', [u.id]); await ctx.audit(req, 'user_force_logout', 'user', u.id); res.json({ ok: true }); }));
  r.post('/admin/users/:id/unlock', M, wrap(async (req, res) => { const u = await target(req); await db.q('UPDATE users SET failed_count=0, locked_until=NULL WHERE id=$1', [u.id]); await ctx.audit(req, 'user_unlock', 'user', u.id); res.json({ ok: true }); }));
  r.post('/admin/users/:id/reset-2fa', ctx.ownerOnly, ctx.reauth, wrap(async (req, res) => { const u = await target(req, { allowStaff: true }); await db.q("UPDATE users SET totp_enabled=false, totp_secret=NULL, prefs = prefs - 'recovery' WHERE id=$1", [u.id]); await ctx.audit(req, 'user_reset_2fa', 'user', u.id); await ctx.secLog(req, '2fa_reset_by_owner', u.id); res.json({ ok: true }); }));
  r.delete('/admin/users/:id', M, ctx.reauth, wrap(async (req, res) => { const u = await target(req); if (u.is_owner) throw forbid(); await ctx.audit(req, 'user_delete', 'user', u.id, { username: u.username }, null); await db.q('DELETE FROM users WHERE id=$1', [u.id]); res.json({ ok: true }); }));
  r.put('/admin/users/:id/roles', ctx.ownerOnly, wrap(async (req, res) => {
    const u = await db.one('SELECT * FROM users WHERE id=$1', [int(req.params.id)]); if (!u) throw nf(); if (u.is_owner) throw bad('The Owner holds every permission by definition');
    const ids = (req.body.role_ids || []).map(x => int(x)), before = await db.q('SELECT role_id FROM user_roles WHERE user_id=$1', [u.id]);
    await db.tx(async t => { await t.q('DELETE FROM user_roles WHERE user_id=$1', [u.id]); for (const id of ids) await t.q('INSERT INTO user_roles VALUES ($1,$2)', [u.id, id]); });
    await ctx.audit(req, 'user_roles', 'user', u.id, before.map(x => x.role_id), ids); res.json({ ok: true });
  }));

  // ---------- sanctions ----------
  const NEED = { warn: 'WARN_USER', timeout: 'TIMEOUT_USER', ban: 'BAN_USER', unban: 'BAN_USER' };
  r.post('/staff/users/:id/sanction', ctx.authed, wrap(async (req, res) => {
    const type = oneOf(req.body.type, Object.keys(NEED), 'type'); if (!can(req.user, NEED[type])) throw forbid(`Missing permission: ${NEED[type]}`);
    const u = await target(req), reason = str(req.body.reason, 'Reason', { min: 3, max: 1000 }), minutes = req.body.minutes ? int(req.body.minutes, 'minutes') : null;
    if (type === 'timeout' && (!minutes || minutes > 43200)) throw bad('Timeout needs 1–43200 minutes');
    let until = null; if (minutes && ['timeout', 'ban'].includes(type)) until = new Date(Date.now() + minutes * 60000);
    if (type === 'warn') until = new Date(Date.now() + 7 * 86400000); // warnings expire after one week
    if (type === 'ban' && !minutes) until = new Date('9999-12-31'); // permanent
    await db.tx(async t => {
      await t.q('INSERT INTO sanctions (user_id,type,reason,evidence,staff_id,duration_minutes,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7)', [u.id, type, reason, req.body.evidence || null, req.user.id, minutes, until]);
      if (type === 'timeout') await t.q('UPDATE users SET muted_until=$2 WHERE id=$1', [u.id, until]);
      if (type === 'ban') { await t.q('UPDATE users SET banned_until=$2, ban_reason=$3 WHERE id=$1', [u.id, until, reason]); }
      if (type === 'unban') { await t.q('UPDATE users SET banned_until=NULL, ban_reason=NULL, muted_until=NULL WHERE id=$1', [u.id]); await t.q("UPDATE sanctions SET revoked_at=now() WHERE user_id=$1 AND type IN ('ban','timeout') AND revoked_at IS NULL", [u.id]); }
    });
    if (type === 'warn') { // auto-send the warning as a private conversation titled "Warning"
      const clean = (s, n) => String(s || '').replace(/\[\/?(quote|img|url)[^\]]*\]/gi, '').slice(0, n), comment = clean(req.body.comment, 1000), subject = clean(req.body.subject, 200), message = clean(req.body.message, 1000);
      const body = [`${u.username}, you received a warning from the moderator: [b]${req.user.username}[/b]`, `Reason: ${reason}`, `Moderator's comment: ${comment}`, '', ...(subject || message ? ['Details:', `[quote]Subject: ${subject}\nMessage: ${message}[/quote]`] : []), 'Warning will be removed in 1 week after the issue', 'When you reach 3 warnings, your forum account will be blocked.'].join('\n');
      await db.tx(async t => {
        const c = await t.one("INSERT INTO conversations (title) VALUES ('Warning') RETURNING id"); await t.q('INSERT INTO conversation_users (conversation_id,user_id) VALUES ($1,$2),($1,$3)', [c.id, req.user.id, u.id]);
        const m = await t.one('INSERT INTO messages (conversation_id,sender_id,body) VALUES ($1,$2,$3) RETURNING id', [c.id, req.user.id, body]); await t.q('UPDATE conversation_users SET last_read_message_id=$2 WHERE conversation_id=$1 AND user_id=$3', [c.id, m.id, req.user.id]);
      });
    }
    await ctx.notify(u.id, 'sanction', { type, reason }); await ctx.mail.send(u.email, 'sanction', { username: u.username, type, reason, until: until ? until.toISOString() : 'n/a' });
    await ctx.audit(req, 'sanction_' + type, 'user', u.id, null, { minutes, reason }, reason); res.status(201).json({ ok: true, until });
  }));
  r.get('/staff/sanctions', ctx.authed, wrap(async (req, res) => {
    if (!(can(req.user, 'WARN_USER') || can(req.user, 'BAN_USER') || can(req.user, 'TIMEOUT_USER'))) throw forbid();
    res.json(await db.q('SELECT s.*, u.username, st.username AS staff FROM sanctions s JOIN users u ON u.id=s.user_id LEFT JOIN users st ON st.id=s.staff_id ORDER BY s.id DESC LIMIT 200'));
  }));

  // ---------- roles & permissions (Owner) ----------
  r.get('/admin/permissions', M, (req, res) => res.json(Object.entries(PERMS).map(([key, description]) => ({ key, description }))));
  r.get('/admin/roles', M, wrap(async (req, res) => res.json(await db.q("SELECT r.*, COALESCE((SELECT json_agg(perm_key) FROM role_permissions WHERE role_id=r.id),'[]') AS perms, (SELECT count(*)::int FROM user_roles WHERE role_id=r.id) AS members FROM roles r ORDER BY sort,id"))));
  const setPerms = async (t, id, perms) => { await t.q('DELETE FROM role_permissions WHERE role_id=$1', [id]); for (const p of perms) { if (!PERMS[p]) throw bad('Unknown permission ' + p); await t.q('INSERT INTO role_permissions VALUES ($1,$2)', [id, p]); } };
  r.post('/admin/roles', ctx.ownerOnly, wrap(async (req, res) => { const b = req.body; const role = await db.tx(async t => { const x = await t.one('INSERT INTO roles (name,color,is_staff,sort) VALUES ($1,$2,$3,$4) RETURNING *', [str(b.name, 'Name', { max: 40 }), b.color || '#7c5cff', !!b.is_staff, +b.sort || 50]); await setPerms(t, x.id, Array.isArray(b.perms) ? b.perms : (b.is_staff ? DEFAULT_STAFF_PERMS : DEFAULT_MEMBER_PERMS)); return x; }); await ctx.audit(req, 'role_create', 'role', role.id, null, b); res.status(201).json(role); }));
  r.patch('/admin/roles/:id', ctx.ownerOnly, wrap(async (req, res) => { const id = int(req.params.id), b = req.body, old = await db.one('SELECT * FROM roles WHERE id=$1', [id]); if (!old) throw nf();
    const before = await db.q('SELECT perm_key FROM role_permissions WHERE role_id=$1', [id]);
    await db.tx(async t => { await t.q('UPDATE roles SET name=COALESCE($2,name), color=COALESCE($3,color), is_staff=COALESCE($4,is_staff), sort=COALESCE($5,sort) WHERE id=$1', [id, b.name ?? null, b.color ?? null, b.is_staff ?? null, b.sort ?? null]); if (Array.isArray(b.perms)) await setPerms(t, id, b.perms); });
    await ctx.audit(req, 'role_update', 'role', id, { name: old.name, perms: before.map(x => x.perm_key) }, b); res.json({ ok: true }); }));
  r.delete('/admin/roles/:id', ctx.ownerOnly, ctx.reauth, wrap(async (req, res) => { const role = await db.one('SELECT * FROM roles WHERE id=$1', [int(req.params.id)]); if (!role) throw nf(); if (role.is_default) throw bad('The default role cannot be deleted'); await db.q('DELETE FROM roles WHERE id=$1', [role.id]); await ctx.audit(req, 'role_delete', 'role', role.id, { name: role.name }, null); res.json({ ok: true }); }));

  // ---------- security / IP / audit ----------
  r.get('/admin/ip', ctx.need('VIEW_IP'), wrap(async (req, res) => {
    const ip = str(req.query.ip, 'ip', { max: 64 }); await ctx.audit(req, 'ip_search', 'ip', ip);
    res.json({ users: await db.q('SELECT id,username,reg_ip,last_ip,created_at FROM users WHERE reg_ip=$1 OR last_ip=$1', [ip]), sessions: await db.q('SELECT s.id,u.username,s.created_at,s.last_active_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.ip=$1 ORDER BY s.id DESC LIMIT 50', [ip]),
      attempts: await db.q('SELECT username,success,created_at FROM login_attempts WHERE ip=$1 ORDER BY id DESC LIMIT 100', [ip]), events: await db.q('SELECT event,user_id,created_at FROM security_logs WHERE ip=$1 ORDER BY id DESC LIMIT 100', [ip]) });
  }));
  r.get('/admin/security', ctx.need('VIEW_SECURITY'), wrap(async (req, res) => {
    const g = q => db.one(q);
    res.json({ failed_24h: (await g("SELECT count(*)::int n FROM login_attempts WHERE NOT success AND created_at > now()-interval '24 hours'")).n, success_24h: (await g("SELECT count(*)::int n FROM login_attempts WHERE success AND created_at > now()-interval '24 hours'")).n,
      locked: await db.q('SELECT id,username,locked_until FROM users WHERE locked_until > now()'), twofa_enabled: (await g('SELECT count(*)::int n FROM users WHERE totp_enabled')).n, active_sessions: (await g('SELECT count(*)::int n FROM sessions WHERE revoked_at IS NULL AND expires_at>now()')).n,
      top_failing_ips: await db.q("SELECT ip, count(*)::int n FROM login_attempts WHERE NOT success AND created_at > now()-interval '24 hours' GROUP BY ip ORDER BY n DESC LIMIT 10"), recent: await db.q("SELECT s.event,s.ip,s.created_at,u.username FROM security_logs s LEFT JOIN users u ON u.id=s.user_id WHERE s.event NOT IN ('login') ORDER BY s.id DESC LIMIT 50"),
      spam_24h: (await g("SELECT count(*)::int n FROM security_logs WHERE event LIKE 'spam_%' AND created_at > now()-interval '24 hours'")).n });
  }));
  r.get('/admin/login-attempts', ctx.need('VIEW_SECURITY'), wrap(async (req, res) => { const { limit, offset } = paging(req, 50, 200); res.json(await db.q(`SELECT id,username,ip,success,created_at FROM login_attempts WHERE ($1::boolean IS NOT TRUE OR NOT success) ORDER BY id DESC LIMIT ${limit} OFFSET ${offset}`, [req.query.failed === '1' ? true : null])); }));
  r.get('/admin/audit', ctx.need('VIEW_AUDIT'), wrap(async (req, res) => {
    const { limit, offset } = paging(req, 50, 200), q = req.query, ip = can(req.user, 'VIEW_IP');
    const rows = await db.q(`SELECT id,actor_id,actor_name,actor_role,action,target_type,target_id,${ip ? 'ip' : 'NULL::text AS ip'},before,after,reason,created_at FROM audit_logs
      WHERE ($1::text IS NULL OR action LIKE $1||'%') AND ($2::int IS NULL OR actor_id=$2) AND ($3::text IS NULL OR target_type=$3) AND ($4::timestamptz IS NULL OR created_at>=$4) ORDER BY id DESC LIMIT ${limit} OFFSET ${offset}`,
      [q.action || null, q.actor_id ? int(q.actor_id) : null, q.target_type || null, q.since || null]);
    if (q.format === 'csv') { res.type('text/csv').send(csv(rows)); } else res.json(rows);
  }));

  // ---------- settings ----------
  r.get('/admin/settings', ctx.staff, wrap(async (req, res) => { const rows = await db.q('SELECT key,value,updated_at FROM settings ORDER BY key'); res.json(rows); }));
  r.put('/admin/settings/:key', ctx.authed, wrap(async (req, res) => {
    const key = req.params.key; if (!(key in DEFAULT_SETTINGS)) throw bad('Unknown setting'); const v = req.body.value;
    const content = ['theme', 'seo', 'tagline', 'site_name', 'footer_a', 'footer_b', 'footer_since'].includes(key); if (!(req.user.is_owner || (content && can(req.user, 'MANAGE_CONTENT')))) throw forbid('Owner only');
    if (typeof v !== typeof DEFAULT_SETTINGS[key] || Array.isArray(v) !== Array.isArray(DEFAULT_SETTINGS[key])) throw bad(`Wrong value type for ${key}`);
    if (key === 'theme' && typeof v.custom_css === 'string' && v.custom_css !== (await ctx.setting('theme')).custom_css && !req.user.is_owner) throw forbid('Custom CSS is Owner-only');
    if (typeof v === 'number' && (v < 0 || v > 1e6)) throw bad('Number out of range');
    const old = await ctx.setting(key); await ctx.setSetting(key, v, req.user.id); await ctx.audit(req, 'setting_update', 'setting', key, old, v); res.json({ ok: true });
  }));
  r.post('/admin/maintenance', ctx.ownerOnly, wrap(async (req, res) => { const v = { on: !!req.body.on, message: String(req.body.message || 'Back soon!').slice(0, 300) }; await ctx.setSetting('maintenance', v, req.user.id); await ctx.audit(req, 'maintenance', 'setting', 'maintenance', null, v); res.json(v); }));
  r.post('/admin/purge', ctx.ownerOnly, wrap(async (req, res) => { const out = await purge(db, ctx.setting); await ctx.audit(req, 'purge', 'system', null, null, out); res.json(out); }));

  // ---------- analytics ----------
  r.get('/admin/analytics', ctx.need('VIEW_ANALYTICS'), wrap(async (req, res) => {
    const days = Math.min(Math.max(+req.query.days || 30, 1), 365);
    res.json({ views: await db.q("SELECT day, sum(views)::int views FROM page_views WHERE day > current_date - $1::int GROUP BY day ORDER BY day", [days]), visitors: await db.q('SELECT day, count(*)::int visitors FROM visitors WHERE day > current_date - $1::int GROUP BY day ORDER BY day', [days]),
      top_pages: await db.q('SELECT path, sum(views)::int views FROM page_views WHERE day > current_date - $1::int GROUP BY path ORDER BY views DESC LIMIT 20', [days]), devices: await db.q('SELECT device, count(*)::int n FROM visitors WHERE day > current_date - $1::int GROUP BY device ORDER BY n DESC', [days]),
      browsers: await db.q('SELECT browser, count(*)::int n FROM visitors WHERE day > current_date - $1::int GROUP BY browser ORDER BY n DESC', [days]), referrers: await db.q('SELECT referrer, count(*)::int n FROM visitors WHERE referrer IS NOT NULL AND day > current_date - $1::int GROUP BY referrer ORDER BY n DESC LIMIT 10', [days]),
      signups: await db.q('SELECT created_at::date AS day, count(*)::int n FROM users WHERE created_at > now() - ($1 || \' days\')::interval GROUP BY 1 ORDER BY 1', [String(days)]), posts: await db.q('SELECT created_at::date AS day, count(*)::int n FROM posts WHERE created_at > now() - ($1 || \' days\')::interval GROUP BY 1 ORDER BY 1', [String(days)]) });
  }));

  // ---------- export ----------
  r.get('/admin/export/:table', ctx.ownerOnly, ctx.reauth, wrap(async (req, res) => {
    const cols = EXPORTS[req.params.table]; if (!cols) throw bad('Table not exportable'); const rows = await db.q(`SELECT ${cols} FROM ${req.params.table} ORDER BY 1 LIMIT 100000`);
    await ctx.audit(req, 'export', 'table', req.params.table, null, { rows: rows.length });
    if (req.query.format === 'json') return res.json(rows); res.set('Content-Disposition', `attachment; filename="${req.params.table}.csv"`).type('text/csv').send(csv(rows));
  }));

  // ---------- backups (JSON logical dump; sessions excluded) ----------
  async function tableOrder(q) {
    const tabs = (await q("SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE'")).map(x => x.table_name).filter(t => t !== 'sessions');
    const fks = await q("SELECT c.conrelid::regclass::text AS child, c.confrelid::regclass::text AS parent FROM pg_constraint c WHERE c.contype='f' AND connamespace='public'::regnamespace");
    const deps = new Map(tabs.map(t => [t, new Set()])); for (const f of fks) if (f.child !== f.parent && deps.has(f.child) && deps.has(f.parent)) deps.get(f.child).add(f.parent);
    const out = [], done = new Set(); while (out.length < tabs.length) { const next = tabs.filter(t => !done.has(t) && [...deps.get(t)].every(d => done.has(d))); if (!next.length) { out.push(...tabs.filter(t => !done.has(t))); break; } next.forEach(t => { done.add(t); out.push(t); }); } return out;
  }
  const B = ctx.ownerOnly;
  r.get('/admin/backups', B, wrap(async (req, res) => res.json(await db.q('SELECT b.*, u.username AS by FROM backups b LEFT JOIN users u ON u.id=b.created_by ORDER BY b.id DESC LIMIT 100'))));
  r.post('/admin/backups', B, ctx.reauth, wrap(async (req, res) => {
    const rec = await db.one("INSERT INTO backups (kind,status,created_by) VALUES ('manual','running',$1) RETURNING id", [req.user.id]);
    try {
      const order = await tableOrder(db.q), data = {}; for (const t of order) data[t] = await db.q(`SELECT * FROM ${t}`);
      const file = `backup-${new Date().toISOString().replace(/[:.]/g, '-')}.json`; await fs.mkdir(cfg.backupDir, { recursive: true });
      const body = JSON.stringify({ version: 1, created: new Date().toISOString(), order, data }); await fs.writeFile(path.join(cfg.backupDir, file), body, { mode: 0o600 });
      await db.q("UPDATE backups SET status='ok', filename=$2, size=$3 WHERE id=$1", [rec.id, file, body.length]); await ctx.audit(req, 'backup_create', 'backup', rec.id); res.status(201).json({ id: rec.id, file });
    } catch (e) { await db.q("UPDATE backups SET status='failed', error=$2 WHERE id=$1", [rec.id, String(e.message).slice(0, 300)]); throw e; }
  }));
  r.get('/admin/backups/:id/download', B, ctx.reauth, wrap(async (req, res) => { const b = await db.one("SELECT filename FROM backups WHERE id=$1 AND status='ok'", [int(req.params.id)]); if (!b) throw nf(); await ctx.audit(req, 'backup_download', 'backup', req.params.id); res.download(path.resolve(cfg.backupDir, b.filename)); }));
  r.post('/admin/backups/:id/restore', B, ctx.reauth, wrap(async (req, res) => {
    if (req.body.confirm !== 'RESTORE') throw bad('Type RESTORE to confirm');
    const b = await db.one("SELECT filename FROM backups WHERE id=$1 AND status='ok'", [int(req.params.id)]); if (!b) throw nf();
    const dump = JSON.parse(await fs.readFile(path.join(cfg.backupDir, b.filename), 'utf8'));
    const valid = new Set(await tableOrder(db.q)); for (const t of dump.order) if (!valid.has(t)) throw bad('Backup contains unknown table ' + t);
    await db.tx(async t => {
      await t.q(`TRUNCATE ${[...valid].join(',')}, sessions RESTART IDENTITY CASCADE`);
      for (const tab of dump.order) { const rows = dump.data[tab] || []; if (!rows.length) continue; await t.q(`INSERT INTO ${tab} OVERRIDING SYSTEM VALUE SELECT * FROM json_populate_recordset(null::${tab}, $1::json)`, [JSON.stringify(rows)]); }
      for (const s of await t.q("SELECT c.table_name t, c.column_name col FROM information_schema.columns c WHERE c.table_schema='public' AND c.is_identity='YES'")) await t.q(`SELECT setval(pg_get_serial_sequence('${s.t}','${s.col}'), GREATEST((SELECT COALESCE(max(${s.col}),0) FROM ${s.t}),1), (SELECT count(*)>0 FROM ${s.t}))`);
    });
    await db.q('INSERT INTO audit_logs (actor_id,actor_name,actor_role,action,target_type,target_id,ip) VALUES ($1,$2,$3,$4,$5,$6,$7)', [req.user.id, req.user.username, 'Owner', 'backup_restore', 'backup', String(req.params.id), req.ip]).catch(() => {});
    cfg._cacheBust?.(); res.json({ ok: true, note: 'All sessions were ended. Log in again.' });
  }));
  r.delete('/admin/backups/:id', B, ctx.reauth, wrap(async (req, res) => { const b = await db.one('DELETE FROM backups WHERE id=$1 RETURNING filename', [int(req.params.id)]); if (b?.filename) await fs.unlink(path.join(cfg.backupDir, b.filename)).catch(() => {}); await ctx.audit(req, 'backup_delete', 'backup', req.params.id); res.json({ ok: true }); }));

  // ---------- live dashboard (Server-Sent Events) ----------
  async function snapshot() {
    const one = async q => (await db.one(q)).n;
    return { at: new Date().toISOString(), online: await one("SELECT count(*)::int n FROM users WHERE last_active_at > now()-interval '5 minutes'"), users: await one('SELECT count(*)::int n FROM users'), threads: await one('SELECT count(*)::int n FROM threads WHERE deleted_at IS NULL'), posts: await one('SELECT count(*)::int n FROM posts WHERE deleted_at IS NULL'),
      posts_24h: await one("SELECT count(*)::int n FROM posts WHERE created_at > now()-interval '24 hours'"), signups_24h: await one("SELECT count(*)::int n FROM users WHERE created_at > now()-interval '24 hours'"), failed_logins_1h: await one("SELECT count(*)::int n FROM login_attempts WHERE NOT success AND created_at > now()-interval '1 hour'"),
      open_reports: await one('SELECT count(*)::int n FROM reports r JOIN statuses s ON s.id=r.status_id WHERE NOT s.is_closed'),
      banned: await one('SELECT count(*)::int n FROM users WHERE banned_until > now()'), active_sessions: await one('SELECT count(*)::int n FROM sessions WHERE revoked_at IS NULL AND expires_at>now()'), pending_name_changes: await one("SELECT count(*)::int n FROM name_changes WHERE status='pending'"), awaiting_approval: await one('SELECT count(*)::int n FROM threads WHERE NOT approved AND deleted_at IS NULL') };
  }
  r.get('/admin/dashboard', ctx.staff, wrap(async (req, res) => res.json(await snapshot())));
  r.get('/admin/live', ctx.staff, (req, res) => {
    res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache, no-transform', Connection: 'keep-alive' }); res.flushHeaders?.();
    let closed = false; const tick = async () => { if (closed) return; try { res.write(`data: ${JSON.stringify(await snapshot())}\n\n`); } catch {} };
    tick(); const iv = setInterval(tick, 5000); req.on('close', () => { closed = true; clearInterval(iv); });
  });

  // ---------- username change approvals ----------
  const NC = (req, res, next) => (can(req.user, 'MANAGE_USERS') || can(req.user, 'BAN_USER')) ? next() : next(forbid());
  r.get('/admin/name-changes', ctx.authed, NC, wrap(async (req, res) => res.json(await db.q("SELECT n.*, u.username AS current_name FROM name_changes n JOIN users u ON u.id=n.user_id ORDER BY (n.status='pending') DESC, n.id DESC LIMIT 100"))));
  r.post('/admin/name-changes/:id', ctx.authed, NC, wrap(async (req, res) => {
    const id = int(req.params.id), approve = req.body.approve === true, note = req.body.note ? String(req.body.note).slice(0, 300) : null;
    const out = await db.tx(async t => {
      const c = await t.one("SELECT * FROM name_changes WHERE id=$1 AND status='pending' FOR UPDATE", [id]); if (!c) throw nf('Request not found or already decided');
      if (approve) {
        if (await t.one('SELECT 1 x FROM users WHERE lower(username)=lower($1) AND id<>$2', [c.new_name, c.user_id])) throw new HttpError(409, 'That username is now taken');
        await t.q('UPDATE users SET display_name = CASE WHEN display_name=username THEN $2 ELSE display_name END, username=$2 WHERE id=$1', [c.user_id, c.new_name]);
      }
      await t.q('UPDATE name_changes SET status=$2, note=$3, decided_by=$4, decided_at=now() WHERE id=$1', [id, approve ? 'approved' : 'rejected', note, req.user.id]);
      return c;
    });
    await ctx.audit(req, approve ? 'username_change_approved' : 'username_change_rejected', 'user', out.user_id, { username: out.old_name }, { username: out.new_name }, note);
    await ctx.notify(out.user_id, 'username_change', { status: approve ? 'approved' : 'rejected', new_name: out.new_name });
    res.json({ ok: true });
  }));

  r.get('/admin/users/:id/related', ctx.need('VIEW_IP'), wrap(async (req, res) => { // other accounts that used the same IP address (possible alts)
    const id = +req.params.id; if (!id) throw bad('Bad id');
    res.json(await db.q(`SELECT DISTINCT u.id, u.username, u.status, u.created_at, u.last_active_at, s2.ip FROM sessions s1 JOIN sessions s2 ON s2.ip=s1.ip AND s2.user_id<>s1.user_id JOIN users u ON u.id=s2.user_id WHERE s1.user_id=$1 AND s1.ip IS NOT NULL ORDER BY u.username LIMIT 50`, [id]));
  }));
  r.get('/admin/staff', ctx.authed, ctx.staff, wrap(async (req, res) => res.json({ target: await ctx.setting('admin_daily_minutes'), rows: await db.q(`SELECT u.id,u.username,u.is_owner,u.last_active_at,u.last_login_at,u.totp_enabled,(u.last_active_at > now()-interval '5 minutes') AS online,
      COALESCE((SELECT minutes FROM user_activity a WHERE a.user_id=u.id AND a.day=CURRENT_DATE),0) AS minutes_today,
      COALESCE((SELECT minutes FROM user_activity a WHERE a.user_id=u.id AND a.day=CURRENT_DATE-1),0) AS minutes_yesterday,
      COALESCE((SELECT json_agg(json_build_object('name',r.name,'color',r.color)) FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=u.id),'[]') AS roles,
      (SELECT count(DISTINCT rp.perm_key)::int FROM user_roles ur JOIN role_permissions rp ON rp.role_id=ur.role_id WHERE ur.user_id=u.id) AS perm_count,
      (SELECT count(*)::int FROM audit_logs a WHERE a.actor_id=u.id AND a.created_at>now()-interval '7 days') AS actions_7d
    FROM users u WHERE u.is_owner OR EXISTS (SELECT 1 FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=u.id AND r.is_staff) ORDER BY u.is_owner DESC, u.username`) })));
  return r;
}
