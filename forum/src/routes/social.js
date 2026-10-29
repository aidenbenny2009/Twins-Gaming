import { Router } from 'express';
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { wrap, bad, str, int, oneOf, paging, HttpError, forbid, nf } from '../util.js';
import { sniffImage, verifyPassword } from '../security.js';

export default function (ctx) {
  const r = Router(), { db, cfg } = ctx, can = ctx.can;
  const byName = async name => { const u = await db.one("SELECT * FROM users WHERE lower(username)=lower($1) AND status='active'", [String(name)]); if (!u) throw nf('User not found'); return u; };

  // ---- uploads (raw image body; type verified by magic bytes, never by client claim) ----
  r.post('/uploads', ctx.authed, ctx.canWrite, ctx.limit(40, 3600_000), wrap(async (req, res) => {
    if (!can(req.user, 'UPLOAD')) throw forbid('You cannot upload files');
    const buf = req.body; if (!Buffer.isBuffer(buf) || !buf.length) throw bad('Send the image as the raw request body with an image/* Content-Type');
    const maxMb = await ctx.setting('max_upload_mb'); if (buf.length > maxMb * 1048576) throw new HttpError(413, `Image is larger than ${maxMb} MB`);
    const kind = sniffImage(buf); if (!kind) throw bad('Only PNG, JPEG, GIF and WebP images are allowed');
    const filename = crypto.randomBytes(16).toString('hex') + '.' + kind.ext;
    await fs.mkdir(cfg.uploadDir, { recursive: true }); await fs.writeFile(path.join(cfg.uploadDir, filename), buf, { mode: 0o644 });
    const m = await db.one('INSERT INTO media (owner_id,filename,original_name,title,alt,category,mime,size) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id,filename,mime,size',
      [req.user.id, filename, (req.query.name || '').toString().slice(0, 120) || null, (req.query.title || '').toString().slice(0, 120) || null, (req.query.alt || '').toString().slice(0, 200) || null, (req.query.category || 'Other').toString().slice(0, 40), kind.mime, buf.length]);
    res.status(201).json({ ...m, url: '/uploads/' + filename });
  }));
  r.post('/me/avatar', ctx.authed, wrap(async (req, res) => { // kind: avatar | banner
    const kind = oneOf(req.body.kind || 'avatar', ['avatar', 'banner'], 'kind');
    const m = await db.one('SELECT filename FROM media WHERE id=$1 AND owner_id=$2', [int(req.body.media_id, 'media_id'), req.user.id]); if (!m) throw nf('Upload not found');
    await db.q(`UPDATE users SET ${kind}_url=$2 WHERE id=$1`, [req.user.id, '/uploads/' + m.filename]); res.json({ ok: true, url: '/uploads/' + m.filename });
  }));

  // ---- notifications ----
  r.get('/notifications', ctx.authed, wrap(async (req, res) => {
    const { limit, offset } = paging(req, 30, 100);
    const items = await db.q(`SELECT id,type,data,read_at,created_at FROM notifications WHERE user_id=$1 ORDER BY id DESC LIMIT ${limit} OFFSET ${offset}`, [req.user.id]);
    const unread = await db.one('SELECT count(*)::int n FROM notifications WHERE user_id=$1 AND read_at IS NULL', [req.user.id]);
    const dm = await db.one('SELECT count(*)::int n FROM messages m JOIN conversation_users cu ON cu.conversation_id=m.conversation_id AND cu.user_id=$1 WHERE m.id>cu.last_read_message_id AND m.sender_id<>$1', [req.user.id]);
    res.json({ items, unread: unread.n, unread_messages: dm.n });
  }));
  r.post('/notifications/read', ctx.authed, wrap(async (req, res) => {
    if (req.body.all) await db.q('UPDATE notifications SET read_at=now() WHERE user_id=$1 AND read_at IS NULL', [req.user.id]);
    else await db.q('UPDATE notifications SET read_at=now() WHERE user_id=$1 AND id=ANY($2::int[]) AND read_at IS NULL', [req.user.id, (req.body.ids || []).map(x => int(x))]);
    res.json({ ok: true });
  }));

  // ---- follows / blocks ----
  for (const [seg, table, col] of [['follow', 'follows', 'followed_id'], ['block', 'blocks', 'blocked_id']]) {
    r.post(`/users/:name/${seg}`, ctx.authed, wrap(async (req, res) => { const u = await byName(req.params.name); if (u.id === req.user.id) throw bad('Not allowed on yourself'); if (seg === 'block' && u.is_owner) throw bad('The Owner cannot be blocked'); await db.q(`INSERT INTO ${table} VALUES ($1,$2) ON CONFLICT DO NOTHING`, [req.user.id, u.id]); if (seg === 'follow') await ctx.notify(u.id, 'follow', { by: req.user.username }); res.json({ ok: true }); }));
    r.delete(`/users/:name/${seg}`, ctx.authed, wrap(async (req, res) => { const u = await byName(req.params.name); await db.q(`DELETE FROM ${table} WHERE user_id=$1 AND ${col}=$2`, [req.user.id, u.id]); res.json({ ok: true }); }));
  }
  r.get('/me/blocks', ctx.authed, wrap(async (req, res) => res.json(await db.q('SELECT u.username FROM blocks b JOIN users u ON u.id=b.blocked_id WHERE b.user_id=$1', [req.user.id]))));
  r.get('/me/following', ctx.authed, wrap(async (req, res) => res.json(await db.q('SELECT u.username,u.avatar_url FROM follows f JOIN users u ON u.id=f.followed_id WHERE f.user_id=$1', [req.user.id]))));

  // ---- profiles ----
  r.get('/users/:name', wrap(async (req, res) => {
    const u = await byName(req.params.name);
    const stats = await db.one(`SELECT (SELECT count(*)::int FROM posts WHERE author_id=$1 AND deleted_at IS NULL) AS posts, (SELECT count(*)::int FROM threads WHERE author_id=$1 AND deleted_at IS NULL) AS threads,
       (SELECT count(*)::int FROM reactions r JOIN posts p ON p.id=r.post_id WHERE p.author_id=$1) AS reactions, (SELECT count(*)::int FROM follows WHERE followed_id=$1) AS followers`, [u.id]);
    const roles = await db.q('SELECT r.name,r.color FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=$1', [u.id]);
    const badges = await db.q('SELECT b.name,b.description,b.icon_url,b.color FROM user_badges ub JOIN badges b ON b.id=ub.badge_id WHERE ub.user_id=$1', [u.id]);
    const me = req.user, hide = u.prefs?.hide_online && !(me && (me.isStaff || me.id === u.id));
    const out = { id: u.id, username: u.username, display_name: u.display_name || u.username, avatar_url: u.avatar_url, banner_url: u.banner_url, bio: u.bio, signature: u.signature, social: u.social, created_at: u.created_at,
      last_active_at: hide ? null : u.last_active_at, is_owner: u.is_owner, roles: [...(u.is_owner ? [{ name: 'Owner', color: '#ffd000' }] : []), ...roles], badges, stats, banned: !!(u.banned_until && u.banned_until > new Date()) };
    out.online = !!(!hide && u.last_active_at && Date.now() - new Date(u.last_active_at).getTime() < 5 * 60_000);
    out.name_history = await db.q("SELECT old_name, new_name, decided_at FROM name_changes WHERE user_id=$1 AND status='approved' ORDER BY id", [u.id]);
    if (me) { const x = await db.one('SELECT EXISTS(SELECT 1 FROM follows WHERE user_id=$1 AND followed_id=$2) AS following, EXISTS(SELECT 1 FROM blocks WHERE user_id=$1 AND blocked_id=$2) AS blocked', [me.id, u.id]); Object.assign(out, x); }
    if (me && can(me, 'VIEW_IP')) Object.assign(out, { reg_ip: u.reg_ip, last_ip: u.last_ip });
    if (me && (me.id === u.id || can(me, 'MANAGE_USERS'))) out.email = u.email;
    res.json(out);
  }));
  r.patch('/me/profile', ctx.authed, wrap(async (req, res) => {
    const b = req.body, sets = [], args = [req.user.id], add = (c, v, cast = '') => { args.push(v); sets.push(`${c}=$${args.length}${cast}`); };
    if ('display_name' in b) add('display_name', str(b.display_name, 'Display name', { min: 2, max: 32 }));
    if ('bio' in b) add('bio', str(b.bio, 'Bio', { max: 1000, optional: true }));
    if ('signature' in b) add('signature', str(b.signature, 'Signature', { max: 1500, optional: true }));
    if ('social' in b) { const s = {}; for (const k of ['website', 'instagram', 'youtube', 'discord', 'twitter']) if (b.social?.[k]) { const v = String(b.social[k]).slice(0, 200); if (k === 'website' || k === 'youtube' || k === 'instagram') { try { if (!/^https?:$/.test(new URL(v).protocol)) throw 0; } catch { throw bad(`${k} must be an http(s) link`); } } s[k] = v; } add('social', JSON.stringify(s), '::jsonb'); }
    if ('prefs' in b) {
      const p = {}; const cur = req.user.prefs || {};
      if (b.prefs.dm) p.dm = oneOf(b.prefs.dm, ['everyone', 'following', 'nobody'], 'dm');
      for (const k of ['hide_online', 'email_notifications', 'hide_profile_posts']) if (k in b.prefs) p[k] = !!b.prefs[k];
      if (b.prefs.theme) p.theme = oneOf(b.prefs.theme, ['dark', 'light', 'auto'], 'theme');
      add('prefs', JSON.stringify({ ...cur, ...p }), '::jsonb');
    }
    if (!sets.length) return res.json({ ok: true });
    await db.q(`UPDATE users SET ${sets.join(',')} WHERE id=$1`, args); res.json({ ok: true });
  }));
  r.post('/me/delete', ctx.authed, ctx.limit(3, 3600_000), wrap(async (req, res) => {
    const u = req.user; if (u.is_owner) throw forbid('The Owner account cannot be deleted'); // transfer ownership first
    if (!(await verifyPassword(String(req.body.password || ''), u.password_hash))) throw new HttpError(401, 'Password is wrong');
    await db.q("UPDATE users SET status='disabled', username='deleted_'||id, display_name='Deleted user', email='deleted-'||id||'@invalid.local', bio=NULL, signature=NULL, avatar_url=NULL, banner_url=NULL, social='{}', totp_secret=NULL, totp_enabled=false, password_hash='!' WHERE id=$1", [u.id]);
    await db.q('UPDATE sessions SET revoked_at=now() WHERE user_id=$1', [u.id]); await ctx.secLog(req, 'account_self_deleted', u.id); res.clearCookie('tg_sid'); res.json({ ok: true });
  }));
  r.get('/users/:name/posts', ctx.limit(60, 60_000), wrap(async (req, res) => { // every message a member wrote (visible forums only)
    const u = await byName(req.params.name);
    res.json(await db.q(`SELECT p.id, p.thread_id, p.created_at, left(p.body, 200) AS snippet, t.title, f.name AS forum, (SELECT count(*)::int FROM posts q WHERE q.thread_id=p.thread_id AND q.id<=p.id AND q.deleted_at IS NULL) AS no
      FROM posts p JOIN threads t ON t.id=p.thread_id JOIN forums f ON f.id=t.forum_id WHERE p.author_id=$1 AND p.deleted_at IS NULL AND t.deleted_at IS NULL AND (f.visibility='public' OR ($2 AND f.visibility='members') OR $3) AND (NOT f.hidden OR $3) ORDER BY p.id DESC LIMIT 100`, [u.id, !!req.user, !!req.user?.isStaff]));
  }));
  r.get('/users/:name/wall', wrap(async (req, res) => { const u = await byName(req.params.name); res.json(await db.q('SELECT w.id,w.body,w.created_at,a.username AS author,a.avatar_url FROM profile_posts w JOIN users a ON a.id=w.author_id WHERE w.profile_id=$1 ORDER BY w.id DESC LIMIT 50', [u.id])); }));
  r.post('/users/:name/wall', ctx.authed, ctx.canWrite, ctx.limit(30, 3600_000), wrap(async (req, res) => {
    const u = await byName(req.params.name), body = str(req.body.body, 'Message', { max: 2000 });
    if (u.prefs?.hide_profile_posts && u.id !== req.user.id) throw forbid('This user has disabled profile posts');
    if (await db.one('SELECT 1 x FROM blocks WHERE user_id=$1 AND blocked_id=$2', [u.id, req.user.id])) throw forbid('You cannot post on this profile');
    const w = await db.one('INSERT INTO profile_posts (profile_id,author_id,body) VALUES ($1,$2,$3) RETURNING id', [u.id, req.user.id, body]);
    if (u.id !== req.user.id) await ctx.notify(u.id, 'profile_post', { by: req.user.username }); res.status(201).json(w);
  }));
  r.delete('/wall/:id', ctx.authed, wrap(async (req, res) => {
    const w = await db.one('SELECT * FROM profile_posts WHERE id=$1', [int(req.params.id)]); if (!w) throw nf();
    if (![w.author_id, w.profile_id].includes(req.user.id) && !can(req.user, 'DELETE_ANY_POST')) throw forbid();
    await db.q('DELETE FROM profile_posts WHERE id=$1', [w.id]); res.json({ ok: true });
  }));
  r.get('/members', ctx.need('VIEW_MEMBERS'), wrap(async (req, res) => {
    const { limit, offset } = paging(req, 30, 100), q = (req.query.q || '').toString().replace(/[%_\\]/g, '\\$&');
    const rows = await db.q(`SELECT id,username,display_name,avatar_url,created_at,last_active_at,prefs->>'hide_online' AS ho FROM users WHERE status='active' AND ($1='' OR username ILIKE $1||'%') ORDER BY username LIMIT ${limit} OFFSET ${offset}`, [q]);
    res.json(rows.map(({ ho, ...u }) => ({ ...u, last_active_at: ho === 'true' ? null : u.last_active_at })));
  }));
  r.get('/online', wrap(async (req, res) => res.json(await db.q("SELECT username,avatar_url FROM users WHERE last_active_at > now() - interval '5 minutes' AND status='active' AND COALESCE(prefs->>'hide_online','false')<>'true' ORDER BY last_active_at DESC LIMIT 100"))));

  // ---- private messages (1:1) with privacy limits ----
  async function dmAllowed(me, other) {
    if (other.status !== 'active') return 'This user is unavailable';
    if (await db.one('SELECT 1 x FROM blocks WHERE (user_id=$1 AND blocked_id=$2) OR (user_id=$2 AND blocked_id=$1)', [me.id, other.id])) return 'You cannot message this user';
    const pref = other.prefs?.dm || 'everyone';
    if (pref === 'nobody' && !me.is_owner) return 'This user does not accept private messages';
    if (pref === 'following' && !me.isStaff && !(await db.one('SELECT 1 x FROM follows WHERE user_id=$1 AND followed_id=$2', [other.id, me.id]))) return 'This user only accepts messages from people they follow';
    return null;
  }
  r.post('/conversations', ctx.authed, ctx.canWrite, ctx.limit(30, 3600_000), wrap(async (req, res) => {
    if (!can(req.user, 'SEND_DM')) throw forbid(); const other = await byName(req.body.to); if (other.id === req.user.id) throw bad('You cannot message yourself');
    const why = await dmAllowed(req.user, other); if (why) throw forbid(why);
    const body = str(req.body.body, 'Message', { max: 10000 });
    const out = await db.tx(async t => {
      let c = await t.one('SELECT c.id FROM conversations c JOIN conversation_users a ON a.conversation_id=c.id AND a.user_id=$1 JOIN conversation_users b ON b.conversation_id=c.id AND b.user_id=$2 LIMIT 1', [req.user.id, other.id]);
      if (!c) { c = await t.one('INSERT INTO conversations (title) VALUES ($1) RETURNING id', [req.body.title ? String(req.body.title).slice(0, 100) : null]); await t.q('INSERT INTO conversation_users (conversation_id,user_id) VALUES ($1,$2),($1,$3)', [c.id, req.user.id, other.id]); }
      const m = await t.one('INSERT INTO messages (conversation_id,sender_id,body) VALUES ($1,$2,$3) RETURNING id', [c.id, req.user.id, body]);
      await t.q('UPDATE conversation_users SET last_read_message_id=$2 WHERE conversation_id=$1 AND user_id=$3', [c.id, m.id, req.user.id]); return c;
    });
    await ctx.notify(other.id, 'message', { by: req.user.username, conversation_id: out.id }); res.status(201).json({ id: out.id });
  }));
  r.get('/conversations', ctx.authed, wrap(async (req, res) => res.json(await db.q(`SELECT c.id, c.title, o.username AS with_user, o.avatar_url,
      (SELECT left(body,120) FROM messages WHERE conversation_id=c.id ORDER BY id DESC LIMIT 1) AS last_message, (SELECT max(created_at) FROM messages WHERE conversation_id=c.id) AS last_at,
      (SELECT count(*)::int FROM messages m WHERE m.conversation_id=c.id AND m.id>me.last_read_message_id AND m.sender_id<>$1) AS unread
      FROM conversation_users me JOIN conversations c ON c.id=me.conversation_id JOIN conversation_users ou ON ou.conversation_id=c.id AND ou.user_id<>$1 JOIN users o ON o.id=ou.user_id WHERE me.user_id=$1 ORDER BY last_at DESC NULLS LAST`, [req.user.id]))));
  async function member(req) { const id = int(req.params.id); const m = await db.one('SELECT 1 x FROM conversation_users WHERE conversation_id=$1 AND user_id=$2', [id, req.user.id]); if (!m) throw nf('Conversation not found'); return id; }
  r.get('/conversations/:id/messages', ctx.authed, wrap(async (req, res) => {
    const id = await member(req);
    const rows = await db.q('SELECT m.id,m.body,m.created_at,u.username AS sender,m.sender_id FROM messages m JOIN users u ON u.id=m.sender_id WHERE m.conversation_id=$1 ORDER BY m.id DESC LIMIT 200', [id]);
    await db.q('UPDATE conversation_users SET last_read_message_id=COALESCE((SELECT max(id) FROM messages WHERE conversation_id=$1),0) WHERE conversation_id=$1 AND user_id=$2', [id, req.user.id]); res.json(rows.reverse());
  }));
  r.post('/conversations/:id/messages', ctx.authed, ctx.canWrite, ctx.limit(120, 3600_000), wrap(async (req, res) => {
    const id = await member(req), body = str(req.body.body, 'Message', { max: 10000 });
    const other = await db.one('SELECT u.* FROM conversation_users cu JOIN users u ON u.id=cu.user_id WHERE cu.conversation_id=$1 AND cu.user_id<>$2', [id, req.user.id]);
    const why = await dmAllowed(req.user, other); if (why) throw forbid(why);
    const m = await db.one('INSERT INTO messages (conversation_id,sender_id,body) VALUES ($1,$2,$3) RETURNING id', [id, req.user.id, body]);
    await db.q('UPDATE conversation_users SET last_read_message_id=$2 WHERE conversation_id=$1 AND user_id=$3', [id, m.id, req.user.id]); await ctx.notify(other.id, 'message', { by: req.user.username, conversation_id: id }); res.status(201).json({ id: m.id });
  }));

  // ---- username change requests (need staff approval) ----
  r.post('/me/username-change', ctx.authed, ctx.canWrite, ctx.limit(5, 86400_000), wrap(async (req, res) => {
    const nn = str(req.body.username, 'Username', { min: 3, max: 24 });
    if (!/^[A-Za-z0-9_]+$/.test(nn)) throw bad('Username may only contain letters, numbers and _');
    if (nn.toLowerCase() === req.user.username.toLowerCase()) throw bad('That is already your username');
    if (await db.one('SELECT 1 x FROM users WHERE lower(username)=lower($1)', [nn])) throw new HttpError(409, 'That username is taken');
    if (await db.one("SELECT 1 x FROM name_changes WHERE status='pending' AND (user_id=$1 OR lower(new_name)=lower($2))", [req.user.id, nn])) throw new HttpError(409, 'A request is already pending');
    const c = await db.one('INSERT INTO name_changes (user_id,old_name,new_name) VALUES ($1,$2,$3) RETURNING id', [req.user.id, req.user.username, nn]);
    await ctx.audit(req, 'username_change_requested', 'user', req.user.id, { username: req.user.username }, { username: nn });
    res.status(201).json({ id: c.id, status: 'pending' });
  }));
  r.get('/me/username-change', ctx.authed, wrap(async (req, res) => res.json(await db.q('SELECT id,old_name,new_name,status,note,created_at,decided_at FROM name_changes WHERE user_id=$1 ORDER BY id DESC LIMIT 5', [req.user.id]))));
  return r;
}
