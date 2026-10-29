import { Router } from 'express';
import { wrap, bad, str, int, bool, oneOf, paging, HttpError, forbid, nf, safeUrl } from '../util.js';

export const visSql = (u, a = 'f') => u?.isStaff ? 'true' : u ? `(${a}.hidden=false AND ${a}.visibility IN ('public','members'))` : `(${a}.hidden=false AND ${a}.visibility='public')`;
const MENTION = /(?:^|[^A-Za-z0-9_])@([A-Za-z0-9_]{3,24})/g;

export default function (ctx) {
  const r = Router(), { db } = ctx;
  const can = ctx.can;

  async function loadThread(req, id, q = db) {
    const t = await q.one(`SELECT t.*, f.name AS forum_name, f.visibility, f.hidden AS forum_hidden, f.locked AS forum_locked, f.reply_perm, f.reply_roles, f.thread_perm, f.require_moderation, f.archived AS forum_archived
      FROM threads t JOIN forums f ON f.id=t.forum_id WHERE t.id=$1`, [id]);
    if (!t) throw nf('Thread not found');
    const u = req.user;
    if (t.forum_hidden && !u?.isStaff) throw nf('Thread not found');
    if (t.visibility === 'staff' && !u?.isStaff) throw nf('Thread not found');
    if (t.visibility === 'members' && !u) throw new HttpError(401, 'Please log in to view this forum');
    if (t.deleted_at && !(u && can(u, 'VIEW_HIDDEN'))) throw nf('Thread not found');
    if (!t.approved && !(u && (u.id === t.author_id || can(u, 'APPROVE_CONTENT')))) throw nf('Thread not found');
    return t;
  }
  async function recount(q, tid) {
    const c = await q.one("SELECT count(*)::int n, max(created_at) la, max(id) lid FROM posts WHERE thread_id=$1 AND deleted_at IS NULL AND NOT hidden", [tid]);
    await q.q('UPDATE threads SET reply_count=GREATEST($2-1,0), last_post_at=COALESCE($3, created_at), last_post_id=$4 WHERE id=$1', [tid, c.n, c.la, c.lid]);
  }
  async function antiSpam(req, body) {
    const u = req.user; if (u.is_owner) return; // owner is unrestricted; everyone else is subject to automatic punishment, logged even for admins
    const [max, dupMin, muteMin] = await Promise.all([ctx.setting('flood_max_per_minute'), ctx.setting('duplicate_window_minutes'), ctx.setting('autopunish_mute_minutes')]);
    const n = await db.one("SELECT count(*)::int n FROM posts WHERE author_id=$1 AND created_at > now() - interval '1 minute'", [u.id]);
    const dup = await db.one("SELECT count(*)::int n FROM posts WHERE author_id=$1 AND body=$2 AND created_at > now() - ($3 || ' minutes')::interval", [u.id, body, String(dupMin)]);
    const why = n.n >= max ? 'flooding' : dup.n > 0 ? 'duplicate' : null;
    if (!why) return;
    await ctx.secLog(req, 'spam_' + why, u.id, { role: u.roleNames.join(',') });
    if (why === 'flooding') {
      await db.q("UPDATE users SET muted_until = now() + ($2 || ' minutes')::interval WHERE id=$1", [u.id, String(muteMin)]);
      await db.q("INSERT INTO sanctions (user_id,type,reason,duration_minutes,expires_at) VALUES ($1,'timeout','Automatic: posting too fast',$2::int, now() + ($3 || ' minutes')::interval)", [u.id, muteMin, String(muteMin)]);
      await ctx.audit(req, 'auto_punish', 'user', u.id, null, { type: 'timeout', minutes: muteMin, why }, 'Automatic anti-spam');
    }
    throw new HttpError(429, why === 'flooding' ? `You are posting too fast. You were timed out for ${muteMin} minutes.` : 'Duplicate post detected.');
  }
  async function afterPost(req, t, post, body, quoteId) {
    const u = req.user, notified = new Set([u.id]);
    const blocked = new Set((await db.q('SELECT user_id FROM blocks WHERE blocked_id=$1', [u.id])).map(x => x.user_id));
    const send = async (uid, type, extra = {}) => { if (notified.has(uid) || blocked.has(uid)) return; notified.add(uid); await ctx.notify(uid, type, { thread_id: t.id, post_id: post.id, title: t.title, by: u.username, ...extra }); };
    if (quoteId) { const q = await db.one('SELECT author_id FROM posts WHERE id=$1', [quoteId]); if (q) await send(q.author_id, 'quote'); }
    const names = [...new Set([...body.matchAll(MENTION)].map(m => m[1].toLowerCase()))].slice(0, 10);
    if (names.length) for (const m of await db.q('SELECT id FROM users WHERE lower(username)=ANY($1::text[]) AND status=\'active\'', [names])) await send(m.id, 'mention');
    for (const f of await db.q('SELECT user_id FROM thread_followers WHERE thread_id=$1', [t.id])) await send(f.user_id, 'reply');
    await db.q('INSERT INTO thread_followers VALUES ($1,$2) ON CONFLICT DO NOTHING', [u.id, t.id]);
  }

  // ---- forum index ----
  r.get('/forums', wrap(async (req, res) => {
    const cats = (await db.q(`SELECT * FROM categories WHERE archived=false ${req.user?.isStaff ? '' : 'AND hidden=false'} ORDER BY sort,id`)).filter(c => req.user?.isStaff || c.visibility === 'all' || (c.visibility === 'members' && req.user));
    const forums = await db.q(`SELECT f.*, (SELECT count(*)::int FROM threads t WHERE t.forum_id=f.id AND t.deleted_at IS NULL AND t.approved) AS thread_count,
        (SELECT count(*)::int FROM posts p JOIN threads t ON t.id=p.thread_id WHERE t.forum_id=f.id AND p.deleted_at IS NULL AND t.deleted_at IS NULL) AS post_count,
        (SELECT json_build_object('id',t.id,'title',t.title,'at',t.last_post_at,'by',u.username) FROM threads t JOIN users u ON u.id=t.author_id WHERE t.forum_id=f.id AND t.deleted_at IS NULL AND t.approved ORDER BY t.last_post_at DESC LIMIT 1) AS last
      FROM forums f WHERE ${visSql(req.user)} ${req.user?.isStaff ? '' : 'AND f.archived=false'} ORDER BY f.sort,f.id`);
    const prefixes = await db.q('SELECT * FROM prefixes ORDER BY sort,id');
    res.json({ categories: cats.map(c => ({ ...c, forums: forums.filter(f => f.category_id === c.id) })), prefixes });
  }));

  r.get('/forums/:id/threads', wrap(async (req, res) => {
    const fid = int(req.params.id), { limit, offset, page } = paging(req, 20);
    const f = await db.one(`SELECT f.* FROM forums f WHERE f.id=$1 AND ${visSql(req.user)}`, [fid]);
    if (!f) { if (!req.user) throw new HttpError(401, 'Please log in'); throw nf('Forum not found'); }
    const showHidden = req.user && can(req.user, 'VIEW_HIDDEN');
    const prefix = req.query.prefix ? int(req.query.prefix, 'prefix') : null;
    const where = `t.forum_id=$1 AND ($2::boolean OR t.deleted_at IS NULL) AND (t.approved OR t.author_id=$3 OR $4::boolean) AND ($5::int IS NULL OR t.prefix_id=$5) AND ($6::boolean OR NOT t.archived)`;
    const args = [fid, !!showHidden, req.user?.id ?? 0, !!(req.user && can(req.user, 'APPROVE_CONTENT')), prefix, req.query.archived === '1'];
    const rows = await db.q(`SELECT t.*, u.username AS author, u.avatar_url AS author_avatar, p.name AS prefix_name, p.color AS prefix_color, p.text_color AS prefix_text,
        (SELECT json_build_object('by',lu.username,'at',lp.created_at) FROM posts lp JOIN users lu ON lu.id=lp.author_id WHERE lp.id=t.last_post_id) AS last
      FROM threads t JOIN users u ON u.id=t.author_id LEFT JOIN prefixes p ON p.id=t.prefix_id WHERE ${where}
      ORDER BY t.pinned DESC, t.last_post_at DESC LIMIT ${limit} OFFSET ${offset}`, args);
    const total = await db.one(`SELECT count(*)::int n FROM threads t WHERE ${where}`, args);
    res.json({ forum: f, threads: rows, total: total.n, page, pages: Math.ceil(total.n / limit) });
  }));

  r.get('/threads/latest', wrap(async (req, res) => {
    const { limit, offset } = paging(req, 20);
    res.json(await db.q(`SELECT t.id,t.title,t.reply_count,t.last_post_at,t.pinned,t.solved,u.username AS author,u.avatar_url AS author_avatar,t.created_at,t.views,f.name AS forum_name,f.id AS forum_id,(SELECT lu.username FROM posts lp JOIN users lu ON lu.id=lp.author_id WHERE lp.id=t.last_post_id) AS last_by FROM threads t JOIN forums f ON f.id=t.forum_id JOIN users u ON u.id=t.author_id
      WHERE t.deleted_at IS NULL AND t.approved AND NOT t.archived AND ${visSql(req.user)} ORDER BY t.last_post_at DESC LIMIT ${limit} OFFSET ${offset}`));
  }));

  async function postList(req, tid, limit, offset) {
    const showHidden = req.user && can(req.user, 'VIEW_HIDDEN');
    const posts = await db.q(`SELECT p.id,p.thread_id,p.author_id,p.created_at,p.edited_at,p.hidden,p.deleted_at,p.quote_post_id,
        CASE WHEN (p.deleted_at IS NOT NULL OR p.hidden) AND NOT $2::boolean THEN '[removed]' ELSE p.body END AS body,
        u.username,u.display_name,u.avatar_url,u.signature,u.created_at AS joined,
        (SELECT count(*)::int FROM posts x WHERE x.author_id=u.id AND x.deleted_at IS NULL) AS author_posts,
        (SELECT json_build_object('id',q.id,'by',qu.username,'body',left(q.body,300)) FROM posts q JOIN users qu ON qu.id=q.author_id WHERE q.id=p.quote_post_id AND q.deleted_at IS NULL) AS quote,
        (SELECT json_object_agg(type,n) FROM (SELECT type,count(*)::int n FROM reactions WHERE post_id=p.id GROUP BY type) rr) AS reactions,
        (SELECT type FROM reactions WHERE post_id=p.id AND user_id=$3) AS my_reaction
      FROM posts p JOIN users u ON u.id=p.author_id WHERE p.thread_id=$1 AND (p.deleted_at IS NULL OR $2::boolean)
      ORDER BY p.created_at,p.id LIMIT ${limit} OFFSET ${offset}`, [tid, !!showHidden, req.user?.id ?? 0]);
    const ids = [...new Set(posts.map(p => p.author_id))];
    const roles = ids.length ? await db.q('SELECT ur.user_id, r.name, r.color FROM user_roles ur JOIN roles r ON r.id=ur.role_id WHERE ur.user_id=ANY($1::int[])', [ids]) : [];
    const owner = ids.length ? await db.q('SELECT id FROM users WHERE id=ANY($1::int[]) AND is_owner', [ids]) : [];
    return posts.map(p => ({ ...p, roles: [...(owner.some(o => o.id === p.author_id) ? [{ name: 'Owner', color: '#ffd000' }] : []), ...roles.filter(x => x.user_id === p.author_id).map(({ name, color }) => ({ name, color }))] }));
  }

  r.get('/threads/:id', wrap(async (req, res) => {
    const id = int(req.params.id), { limit, offset, page } = paging(req, 15, 50);
    const t = await loadThread(req, id);
    db.q('UPDATE threads SET views=views+1 WHERE id=$1', [id]).catch(() => {});
    const total = await db.one('SELECT count(*)::int n FROM posts WHERE thread_id=$1 AND deleted_at IS NULL', [id]);
    const extra = req.user ? await db.one('SELECT EXISTS(SELECT 1 FROM bookmarks WHERE user_id=$1 AND thread_id=$2) AS bookmarked, EXISTS(SELECT 1 FROM thread_followers WHERE user_id=$1 AND thread_id=$2) AS following', [req.user.id, id]) : {};
    const pf = t.prefix_id ? await db.one('SELECT name,color,text_color FROM prefixes WHERE id=$1', [t.prefix_id]) : null;
    res.json({ thread: { ...t, prefix: pf, ...extra }, posts: await postList(req, id, limit, offset), total: total.n, page, pages: Math.ceil(total.n / limit) });
  }));

  // who may post threads / reply in a forum: permission name, VERIFIED, NO_ONE, plus an optional role allow-list
  const allowIn = (u, f, kind) => {
    const perm = f[kind + '_perm'], roles = f[kind + '_roles'];
    if (perm === 'NO_ONE') return false; // "hide Post thread": applies to everyone, owner included
    if (u.is_owner) return true;
    if (Array.isArray(roles) && roles.length) return (u.roles || []).some(r => roles.includes(r.id));
    if (perm === 'VERIFIED') return !!u.email_verified;
    if (perm === 'NO_ONE') return false;
    return can(u, perm);
  };
  // ---- create ----
  const FIELD_TYPES = ['text', 'date', 'time', 'url', 'number'];
  const cleanDef = v => { if (v == null) return null; if (!Array.isArray(v) || v.length > 20) throw bad('Fields must be a list of at most 20'); const seen = new Set(); return v.map(x => { const key = String(x.key || '').toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 30); if (!key || seen.has(key)) throw bad('Every field needs a unique key'); seen.add(key); return { key, label: str(x.label, 'Field label', { max: 60 }), hint: x.hint ? String(x.hint).slice(0, 200) : '', type: FIELD_TYPES.includes(x.type) ? x.type : 'text', required: !!x.required }; }); };
  const cleanVals = (def, vals, partial) => { if (!Array.isArray(def) || !def.length) return null; vals = vals && typeof vals === 'object' ? vals : {}; const out = {}; for (const d of def) { let v = vals[d.key]; if (v == null || String(v).trim() === '') { if (d.required && !partial) throw bad(d.label + ' is required'); continue; } v = String(v).trim().slice(0, 500); if (d.type === 'url' && v.split(/\s+/).some(u => !/^https?:\/\//i.test(u))) throw bad(d.label + ' must be a link starting with http(s)://'); if (d.type === 'number' && !/^-?\d+(\.\d+)?$/.test(v)) throw bad(d.label + ' must be a number'); if (d.type === 'date' && !/^\d{4}-\d{2}-\d{2}$/.test(v)) throw bad(d.label + ' must be a date'); if (d.type === 'time' && !/^\d{2}:\d{2}$/.test(v)) throw bad(d.label + ' must be a time (HH:MM)'); out[d.key] = v; } return out; };
  r.post('/threads', ctx.authed, ctx.canWrite, ctx.limit(30, 3600_000), wrap(async (req, res) => {
    const u = req.user, fid = int(req.body.forum_id, 'forum_id');
    const title = str(req.body.title, 'Title', { min: 3, max: 200 }), body = str(req.body.body, 'Message', { max: 20000 });
    const f = await db.one(`SELECT f.* FROM forums f WHERE f.id=$1 AND ${visSql(u)}`, [fid]); if (!f) throw nf('Forum not found');
    if (f.archived && !u.isStaff) throw forbid('This forum is archived');
    if (f.locked && !can(u, 'LOCK_THREAD')) throw forbid('This forum is locked');
    if (!allowIn(u, f, 'thread')) throw forbid('You cannot create threads here');
    if (await ctx.setting('threads_disabled')) throw forbid('Posting new threads is turned off');
    const catRow = await db.one('SELECT no_threads FROM categories WHERE id=$1', [f.category_id]); if (catRow?.no_threads) throw forbid('Posting threads is turned off in this section');
    for (let p = f.parent_id, n = 0; p && n < 20; n++) { const a = await db.one('SELECT parent_id, thread_perm FROM forums WHERE id=$1', [p]); if (!a) break; if (a.thread_perm === 'NO_ONE') throw forbid('Posting threads is turned off in the parent forum'); p = a.parent_id; }
    let prefix = null;
    if (req.body.prefix_id) { prefix = int(req.body.prefix_id, 'prefix_id'); if (Array.isArray(f.allowed_prefixes) && !f.allowed_prefixes.includes(prefix)) throw bad('Prefix not allowed in this forum'); const pr = await db.one('SELECT advanced FROM prefixes WHERE id=$1', [prefix]); if (!pr) throw bad('Unknown prefix'); if (pr.advanced && !u.is_owner && !u.isStaff) throw forbid('Advanced prefixes are for staff only'); }
    if (!u.email_verified) throw forbid('Confirm your email first');
    await antiSpam(req, body);
    const approved = !f.require_moderation || can(u, 'APPROVE_CONTENT');
    const fvals = cleanVals(f.fields, req.body.fields, false);
    const out = await db.tx(async t => {
      const th = await t.one('INSERT INTO threads (forum_id,author_id,title,prefix_id,approved,fields) VALUES ($1,$2,$3,$4,$5,$6::jsonb) RETURNING *', [fid, u.id, title, prefix, approved, fvals ? JSON.stringify(fvals) : null]);
      const p = await t.one('INSERT INTO posts (thread_id,author_id,body,ip) VALUES ($1,$2,$3,$4) RETURNING *', [th.id, u.id, body, req.ip]);
      await t.q('UPDATE threads SET last_post_id=$2 WHERE id=$1', [th.id, p.id]);
      await t.q('INSERT INTO thread_followers VALUES ($1,$2)', [u.id, th.id]);
      return { th, p };
    });
    await afterPost(req, out.th, out.p, body, null);
    res.status(201).json({ id: out.th.id, approved });
  }));

  r.post('/threads/:id/posts', ctx.authed, ctx.canWrite, ctx.limit(60, 3600_000), wrap(async (req, res) => {
    const u = req.user, id = int(req.params.id), body = str(req.body.body, 'Message', { max: 20000 });
    const t = await loadThread(req, id);
    if (!t.approved) throw forbid('This thread is awaiting approval');
    if ((t.locked || t.forum_locked) && !can(u, 'LOCK_THREAD')) throw forbid('This thread is locked');
    if (t.archived && !can(u, 'ARCHIVE_THREAD')) throw forbid('This thread is archived');
    if (!allowIn(u, t, 'reply')) throw forbid('You cannot reply here');
    if (!u.email_verified) throw forbid('Confirm your email first');
    let qid = null;
    if (req.body.quote_post_id) { qid = int(req.body.quote_post_id, 'quote_post_id'); const q = await db.one('SELECT 1 x FROM posts WHERE id=$1 AND thread_id=$2 AND deleted_at IS NULL', [qid, id]); if (!q) throw bad('Quoted post not found in this thread'); }
    await antiSpam(req, body);
    const p = await db.tx(async tx => {
      const p = await tx.one('INSERT INTO posts (thread_id,author_id,body,quote_post_id,ip) VALUES ($1,$2,$3,$4,$5) RETURNING *', [id, u.id, body, qid, req.ip]);
      await recount(tx, id); return p;
    });
    await afterPost(req, t, p, body, qid);
    res.status(201).json({ id: p.id });
  }));

  // ---- edit / delete / revisions ----
  async function loadPost(req, pid) {
    const p = await db.one('SELECT p.*, t.forum_id, t.locked AS tlocked FROM posts p JOIN threads t ON t.id=p.thread_id WHERE p.id=$1', [pid]);
    if (!p) throw nf('Post not found'); await loadThread(req, p.thread_id); return p;
  }
  r.patch('/posts/:id', ctx.authed, ctx.canWrite, wrap(async (req, res) => {
    const u = req.user, p = await loadPost(req, int(req.params.id)), body = str(req.body.body, 'Message', { max: 20000 });
    const own = p.author_id === u.id;
    if (!(own && can(u, 'EDIT_OWN_POST')) && !can(u, 'EDIT_ANY_POST')) throw forbid();
    if (p.deleted_at) throw bad('Post is deleted');
    if (own && p.tlocked && !can(u, 'EDIT_ANY_POST')) throw forbid('Thread is locked');
    if (body === p.body) return res.json({ ok: true });
    await db.tx(async t => {
      await t.q('INSERT INTO post_revisions (post_id,editor_id,body) VALUES ($1,$2,$3)', [p.id, u.id, p.body]); // keep the previous version
      await t.q('UPDATE posts SET body=$2, edited_at=now(), edited_by=$3 WHERE id=$1', [p.id, body, u.id]);
    });
    if (!own) await ctx.audit(req, 'post_edit', 'post', p.id, { body: p.body.slice(0, 500) }, { body: body.slice(0, 500) });
    res.json({ ok: true });
  }));
  r.delete('/posts/:id', ctx.authed, ctx.canWrite, wrap(async (req, res) => {
    const u = req.user, p = await loadPost(req, int(req.params.id)), own = p.author_id === u.id;
    if (!(own && can(u, 'DELETE_OWN_POST')) && !can(u, 'DELETE_ANY_POST')) throw forbid();
    const first = await db.one('SELECT id FROM posts WHERE thread_id=$1 ORDER BY created_at,id LIMIT 1', [p.thread_id]);
    if (first.id === p.id) throw bad('Delete the whole thread instead of its first post');
    await db.tx(async t => { await t.q('UPDATE posts SET deleted_at=now(), deleted_by=$2 WHERE id=$1', [p.id, u.id]); await recount(t, p.thread_id); });
    if (!own) await ctx.audit(req, 'post_delete', 'post', p.id, null, null, req.body?.reason);
    res.json({ ok: true });
  }));
  r.post('/posts/:id/restore', ctx.need('DELETE_ANY_POST'), wrap(async (req, res) => {
    const p = await loadPost(req, int(req.params.id));
    await db.tx(async t => { await t.q('UPDATE posts SET deleted_at=NULL, deleted_by=NULL, hidden=false WHERE id=$1', [p.id]); await recount(t, p.thread_id); });
    await ctx.audit(req, 'post_restore', 'post', p.id); res.json({ ok: true });
  }));
  r.get('/posts/:id/revisions', ctx.authed, wrap(async (req, res) => {
    const p = await loadPost(req, int(req.params.id));
    if (!(p.author_id === req.user.id || can(req.user, 'VIEW_EDIT_HISTORY'))) throw forbid();
    const rows = await db.q('SELECT v.id, v.body, v.created_at, u.username AS editor FROM post_revisions v LEFT JOIN users u ON u.id=v.editor_id WHERE v.post_id=$1 ORDER BY v.id DESC', [p.id]);
    res.json({ current: p.body, revisions: rows });
  }));

  // ---- reactions, bookmarks, follow ----
  r.post('/posts/:id/react', ctx.authed, ctx.canWrite, ctx.limit(120, 60_000), wrap(async (req, res) => {
    if (!can(req.user, 'REACT')) throw forbid();
    const p = await loadPost(req, int(req.params.id)); const type = req.body.type;
    if (type === null || type === undefined) await db.q('DELETE FROM reactions WHERE post_id=$1 AND user_id=$2', [p.id, req.user.id]);
    else {
      oneOf(type, await ctx.setting('reaction_types'), 'type');
      if (p.author_id === req.user.id) throw bad('You cannot react to your own post');
      const had = await db.one('SELECT 1 x FROM reactions WHERE post_id=$1 AND user_id=$2', [p.id, req.user.id]);
      await db.q('INSERT INTO reactions (post_id,user_id,type) VALUES ($1,$2,$3) ON CONFLICT (post_id,user_id) DO UPDATE SET type=EXCLUDED.type', [p.id, req.user.id, type]);
      if (!had) await ctx.notify(p.author_id, 'reaction', { post_id: p.id, thread_id: p.thread_id, by: req.user.username, type });
    }
    res.json({ ok: true });
  }));
  r.get('/posts/:id/reactions', wrap(async (req, res) => {
    const p = await loadPost(req, int(req.params.id));
    res.json(await db.q('SELECT u.username,u.display_name,u.avatar_url,x.type,x.created_at FROM reactions x JOIN users u ON u.id=x.user_id WHERE x.post_id=$1 ORDER BY x.created_at DESC LIMIT 500', [p.id]));
  }));
  for (const [path, table] of [['bookmark', 'bookmarks'], ['follow', 'thread_followers']]) {
    r.post(`/threads/:id/${path}`, ctx.authed, wrap(async (req, res) => { const t = await loadThread(req, int(req.params.id)); await db.q(`INSERT INTO ${table} (user_id,thread_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, [req.user.id, t.id]); res.json({ ok: true }); }));
    r.delete(`/threads/:id/${path}`, ctx.authed, wrap(async (req, res) => { await db.q(`DELETE FROM ${table} WHERE user_id=$1 AND thread_id=$2`, [req.user.id, int(req.params.id)]); res.json({ ok: true }); }));
  }
  r.get('/me/bookmarks', ctx.authed, wrap(async (req, res) => res.json(await db.q(`SELECT t.id,t.title,t.reply_count,t.last_post_at,f.name AS forum_name,b.created_at FROM bookmarks b JOIN threads t ON t.id=b.thread_id JOIN forums f ON f.id=t.forum_id WHERE b.user_id=$1 AND t.deleted_at IS NULL AND ${visSql(req.user)} ORDER BY b.created_at DESC LIMIT 200`, [req.user.id]))));

  // ---- thread moderation ----
  const ACTIONS = {
    pin: ['PIN_THREAD', 'pinned=true'], unpin: ['PIN_THREAD', 'pinned=false'], lock: ['LOCK_THREAD', 'locked=true'], unlock: ['LOCK_THREAD', 'locked=false'],
    archive: ['ARCHIVE_THREAD', 'archived=true'], unarchive: ['ARCHIVE_THREAD', 'archived=false'], feature: ['FEATURE_THREAD', 'featured=true'], unfeature: ['FEATURE_THREAD', 'featured=false'],
    delete: ['DELETE_ANY_POST', 'deleted_at=now()'], restore: ['DELETE_ANY_POST', 'deleted_at=NULL'], approve: ['APPROVE_CONTENT', 'approved=true'],
    solve: ['MARK_SOLVED', 'solved=true'], unsolve: ['MARK_SOLVED', 'solved=false'],
  };
  async function applyAction(req, t, action, extra = {}) {
    if (action === 'move') {
      if (!can(req.user, 'MOVE_THREAD')) throw forbid('Missing permission: MOVE_THREAD');
      const dest = int(extra.forum_id, 'forum_id'); const f = await db.one('SELECT id FROM forums WHERE id=$1', [dest]); if (!f) throw bad('Destination forum not found');
      await db.q('UPDATE threads SET forum_id=$2 WHERE id=$1', [t.id, dest]); return ctx.audit(req, 'thread_move', 'thread', t.id, { forum_id: t.forum_id }, { forum_id: dest });
    }
    if (action === 'archive' && can(req.user, 'ARCHIVE_THREAD')) { // move into the Archive sub-forum of this forum (or its parent's / sibling Archive)
      const cur = await db.one('SELECT id,parent_id FROM forums WHERE id=$1', [t.forum_id]);
      const arc = cur && await db.one("SELECT id FROM forums WHERE (is_archive OR name ILIKE '%Archive') AND id<>$1 AND (parent_id=$1 OR (parent_id IS NOT NULL AND parent_id=$2)) ORDER BY (parent_id=$1) DESC LIMIT 1", [cur.id, cur.parent_id]);
      if (arc) { await db.q('UPDATE threads SET forum_id=$2, archived=false WHERE id=$1', [t.id, arc.id]); return ctx.audit(req, 'thread_archive', 'thread', t.id, { forum_id: t.forum_id }, { forum_id: arc.id }); }
    }
    const a = ACTIONS[action]; if (!a) throw bad('Unknown action');
    const ownerSolve = (action === 'solve' || action === 'unsolve') && t.author_id === req.user.id; // thread author may mark their own thread solved
    if (!ownerSolve && !can(req.user, a[0])) throw forbid(`Missing permission: ${a[0]}`);
    await db.q(`UPDATE threads SET ${a[1]} WHERE id=$1`, [t.id]);
    if (!ownerSolve) await ctx.audit(req, 'thread_' + action, 'thread', t.id, null, null, extra.reason);
  }
  r.patch('/threads/:id', ctx.authed, ctx.canWrite, wrap(async (req, res) => { // edit title / prefix (author while the thread is open, or staff)
    const t = await loadThread(req, int(req.params.id)); const staff = can(req.user, 'EDIT_ANY_POST');
    if (!staff && !(t.author_id === req.user.id && !t.locked)) throw forbid();
    const b = req.body; const title = b.title === undefined ? null : str(b.title, 'Title', { max: 200 });
    let pid = undefined; if (b.prefix_id !== undefined) { pid = b.prefix_id ? int(b.prefix_id, 'prefix_id') : null; if (pid) { const p = await db.one('SELECT advanced FROM prefixes WHERE id=$1', [pid]); if (!p) throw bad('Unknown prefix'); if (p.advanced && !staff) throw forbid('That prefix is for staff only'); } }
    await db.q('UPDATE threads SET title=COALESCE($2,title), prefix_id=CASE WHEN $4 THEN $3 ELSE prefix_id END WHERE id=$1', [t.id, title, pid ?? null, pid !== undefined]);
    if (b.fields !== undefined) { const fd = await db.one('SELECT fields FROM forums WHERE id=$1', [t.forum_id]); await db.q('UPDATE threads SET fields=$2::jsonb WHERE id=$1', [t.id, (v => v ? JSON.stringify(v) : null)(cleanVals(fd?.fields, b.fields, false))]); }
    await ctx.audit(req, 'thread_edit', 'thread', t.id, { title: t.title, prefix_id: t.prefix_id }, { title: title ?? t.title, prefix_id: pid }); res.json({ ok: true });
  }));
  r.post('/threads/:id/mod', ctx.authed, wrap(async (req, res) => {
    const t = await loadThread(req, int(req.params.id)); await applyAction(req, t, String(req.body.action), req.body); res.json({ ok: true });
  }));
  r.post('/threads/:id/merge', ctx.need('MERGE_THREAD'), wrap(async (req, res) => {
    const src = await loadThread(req, int(req.params.id)), dst = await loadThread(req, int(req.body.into, 'into'));
    if (src.id === dst.id) throw bad('Cannot merge a thread into itself');
    await db.tx(async t => {
      await t.q('UPDATE posts SET thread_id=$2 WHERE thread_id=$1', [src.id, dst.id]);
      await t.q('INSERT INTO bookmarks SELECT user_id,$2,created_at FROM bookmarks WHERE thread_id=$1 ON CONFLICT DO NOTHING', [src.id, dst.id]);
      await t.q('INSERT INTO thread_followers SELECT user_id,$2 FROM thread_followers WHERE thread_id=$1 ON CONFLICT DO NOTHING', [src.id, dst.id]);
      await t.q('DELETE FROM threads WHERE id=$1', [src.id]);
      await recount(t, dst.id);
    });
    await ctx.audit(req, 'thread_merge', 'thread', dst.id, { merged: src.id, title: src.title }, null); res.json({ ok: true, id: dst.id });
  }));
  r.post('/threads/:id/split', ctx.need('SPLIT_THREAD'), wrap(async (req, res) => {
    const src = await loadThread(req, int(req.params.id));
    const ids = (Array.isArray(req.body.post_ids) ? req.body.post_ids : []).map(x => int(x, 'post_id')); if (!ids.length) throw bad('Select at least one post');
    const title = str(req.body.title, 'Title', { min: 3, max: 200 }), fid = req.body.forum_id ? int(req.body.forum_id, 'forum_id') : src.forum_id;
    const sel = await db.q('SELECT * FROM posts WHERE id=ANY($1::int[]) AND thread_id=$2 ORDER BY created_at,id', [ids, src.id]);
    if (sel.length !== new Set(ids).size) throw bad('Some posts do not belong to this thread');
    const first = await db.one('SELECT id FROM posts WHERE thread_id=$1 ORDER BY created_at,id LIMIT 1', [src.id]);
    if (ids.includes(first.id)) throw bad('The first post cannot be split off');
    const out = await db.tx(async t => {
      const nt = await t.one('INSERT INTO threads (forum_id,author_id,title) VALUES ($1,$2,$3) RETURNING id', [fid, sel[0].author_id, title]);
      await t.q('UPDATE posts SET thread_id=$2 WHERE id=ANY($1::int[])', [ids, nt.id]);
      await recount(t, src.id); await recount(t, nt.id); return nt;
    });
    await ctx.audit(req, 'thread_split', 'thread', src.id, null, { new_thread: out.id, posts: ids }); res.json({ ok: true, id: out.id });
  }));
  r.post('/mod/bulk', ctx.need('BULK_MODERATE'), wrap(async (req, res) => {
    const ids = (Array.isArray(req.body.thread_ids) ? req.body.thread_ids : []).map(x => int(x, 'thread_id')); if (!ids.length || ids.length > 100) throw bad('Select 1–100 threads');
    const results = [];
    for (const id of ids) { try { const t = await loadThread(req, id); await applyAction(req, t, String(req.body.action), req.body); results.push({ id, ok: true }); } catch (e) { results.push({ id, ok: false, error: e.message }); } }
    res.json({ results });
  }));
  r.get('/mod/queue', ctx.need('APPROVE_CONTENT'), wrap(async (req, res) => res.json(await db.q('SELECT t.id,t.title,t.created_at,u.username AS author,f.name AS forum_name FROM threads t JOIN users u ON u.id=t.author_id JOIN forums f ON f.id=t.forum_id WHERE NOT t.approved AND t.deleted_at IS NULL ORDER BY t.created_at'))));

  // ---- search ----
  r.get('/search', ctx.limit(60, 60_000), wrap(async (req, res) => {
    const q = str(req.query.q, 'Query', { min: 2, max: 100 }), { limit, offset } = paging(req, 20, 50), scope = req.query.scope || 'threads';
    const fid = req.query.forum_id ? int(req.query.forum_id, 'forum_id') : null;
    if (scope === 'users') { if (!req.user) throw new HttpError(401, 'Please log in'); return res.json(await db.q("SELECT id,username,display_name,avatar_url FROM users WHERE status='active' AND (username ILIKE $1) ORDER BY username LIMIT 20", [q.replace(/[%_\\]/g, '\\$&') + '%'])); }
    const hl = "'StartSel=[[,StopSel=]],MaxFragments=1,MaxWords=25,MinWords=8'";
    if (scope === 'posts') return res.json(await db.q(`SELECT p.id AS post_id, t.id, t.title, u.username AS author, p.created_at, ts_headline('simple', p.body, plainto_tsquery('simple',$1), ${hl}) AS snippet
      FROM posts p JOIN threads t ON t.id=p.thread_id JOIN forums f ON f.id=t.forum_id JOIN users u ON u.id=p.author_id
      WHERE to_tsvector('simple', p.body) @@ plainto_tsquery('simple',$1) AND p.deleted_at IS NULL AND NOT p.hidden AND t.deleted_at IS NULL AND t.approved AND ($2::int IS NULL OR f.id=$2) AND ${visSql(req.user)}
      ORDER BY p.created_at DESC LIMIT ${limit} OFFSET ${offset}`, [q, fid]));
    res.json(await db.q(`SELECT t.id, t.title, t.reply_count, t.last_post_at, f.name AS forum_name, u.username AS author FROM threads t JOIN forums f ON f.id=t.forum_id JOIN users u ON u.id=t.author_id
      WHERE (to_tsvector('simple', t.title) @@ plainto_tsquery('simple',$1) OR t.title ILIKE $3) AND t.deleted_at IS NULL AND t.approved AND ($2::int IS NULL OR f.id=$2) AND ${visSql(req.user)}
      ORDER BY t.last_post_at DESC LIMIT ${limit} OFFSET ${offset}`, [q, fid, '%' + q.replace(/[%_\\]/g, '\\$&') + '%']));
  }));

  // ---- forum structure admin (MANAGE_FORUMS) ----
  const F = ctx.need('MANAGE_FORUMS');
  const PAGES = ['rules'];
  const permOk = async (p) => p === 'VERIFIED' || p === 'NO_ONE' || !!(await db.one('SELECT 1 x FROM permissions WHERE key=$1', [String(p)]));
  const roleIds = (v) => (Array.isArray(v) ? v : []).slice(0, 100).map(x => int(x, 'role'));
  const hasCycle = (parentOf, id) => { const seen = new Set([id]); let p = parentOf.get(id); while (p) { if (seen.has(p)) return true; seen.add(p); p = parentOf.get(p); } return false; };
  async function checkParent(id, parent) { // a forum can never become its own ancestor
    if (!parent) return; const all = await db.q('SELECT id,parent_id FROM forums'), m = new Map(all.map(x => [x.id, x.parent_id])); m.set(id, parent); if (hasCycle(m, id)) throw bad('A forum cannot be placed inside itself or one of its own sub-forums');
  }
  r.post('/admin/categories', F, wrap(async (req, res) => { const c = await db.one('INSERT INTO categories (name,description,sort) VALUES ($1,$2,$3) RETURNING *', [str(req.body.name, 'Name', { max: 80 }), req.body.description || null, +req.body.sort || 0]); await ctx.audit(req, 'category_create', 'category', c.id, null, c); res.status(201).json(c); }));
  r.patch('/admin/categories/:id', F, wrap(async (req, res) => { const id = int(req.params.id), b = req.body; const c = await db.one('UPDATE categories SET name=COALESCE($2,name), description=COALESCE($3,description), sort=COALESCE($4,sort), hidden=COALESCE($5,hidden), archived=COALESCE($6,archived), visibility=COALESCE($7,visibility), color=CASE WHEN $8::text IS NULL THEN color WHEN $8::text=\'\' THEN NULL ELSE $8::text END, collapsed=COALESCE($9,collapsed), no_threads=COALESCE($10,no_threads) WHERE id=$1 RETURNING *', [id, b.name ?? null, b.description ?? null, b.sort ?? null, b.hidden ?? null, b.archived ?? null, b.visibility == null ? null : oneOf(b.visibility, ['all', 'members', 'staff'], 'visibility'), b.color == null ? null : (b.color === '' || /^#[0-9a-f]{6}$/i.test(b.color) ? b.color : (() => { throw bad('Colour must look like #aabbcc'); })()), b.collapsed ?? null, b.no_threads ?? null]); if (!c) throw nf(); await ctx.audit(req, 'category_update', 'category', id, null, c); res.json(c); }));
  r.delete('/admin/categories/:id', F, ctx.reauth, wrap(async (req, res) => { await db.q('DELETE FROM categories WHERE id=$1', [int(req.params.id)]); await ctx.audit(req, 'category_delete', 'category', req.params.id); res.json({ ok: true }); }));
  r.post('/admin/forums', F, wrap(async (req, res) => { const b = req.body; if (b.link_url) safeUrl(b.link_url, 'link_url'); if (b.page_route && !PAGES.includes(b.page_route)) throw bad('Unknown page'); if (b.parent_id) await checkParent(0, int(b.parent_id)); const f = await db.one('INSERT INTO forums (category_id,parent_id,name,description,sort,visibility,link_url,page_route,is_archive) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *', [int(b.category_id, 'category_id'), b.parent_id ? int(b.parent_id) : null, str(b.name, 'Name', { max: 80 }), b.description || null, +b.sort || 0, oneOf(b.visibility || 'public', ['public', 'members', 'staff'], 'visibility'), b.link_url ? safeUrl(b.link_url, 'link_url') : null, b.page_route || null, !!b.is_archive]); await ctx.audit(req, 'forum_create', 'forum', f.id, null, f); res.status(201).json(f); }));
  r.patch('/admin/forums/:id', F, wrap(async (req, res) => {
    const id = int(req.params.id), b = req.body, old = await db.one('SELECT * FROM forums WHERE id=$1', [id]); if (!old) throw nf();
    if (b.visibility) oneOf(b.visibility, ['public', 'members', 'staff'], 'visibility');
    if (b.link_url) b.link_url = safeUrl(b.link_url, 'link_url'); if (b.page_route && !PAGES.includes(b.page_route)) throw bad('Unknown page');
    for (const k of ['thread_perm', 'reply_perm']) if (k in b && !(await permOk(b[k]))) throw bad('Unknown permission: ' + b[k]);
    for (const k of ['thread_roles', 'reply_roles']) if (k in b) b[k] = roleIds(b[k]);
    if ('parent_id' in b && b.parent_id) await checkParent(id, int(b.parent_id));
    const cols = ['category_id', 'parent_id', 'name', 'description', 'icon', 'banner_url', 'sort', 'visibility', 'locked', 'hidden', 'archived', 'allow_attachments', 'require_moderation', 'thread_perm', 'reply_perm', 'link_url', 'page_route', 'is_archive'];
    const set = [], args = [id]; for (const c of cols) if (c in b) { args.push(b[c]); set.push(`${c}=$${args.length}`); }
    for (const k of ['thread_roles', 'reply_roles']) if (k in b) { args.push(Array.isArray(b[k]) && b[k].length ? JSON.stringify(b[k]) : null); set.push(`${k}=$${args.length}::jsonb`); }
    if ('fields' in b) { const def = cleanDef(b.fields); args.push(def && def.length ? JSON.stringify(def) : null); set.push(`fields=$${args.length}::jsonb`); }
    if ('allowed_prefixes' in b) { args.push(b.allowed_prefixes ? JSON.stringify(b.allowed_prefixes) : null); set.push(`allowed_prefixes=$${args.length}::jsonb`); }
    if (!set.length) return res.json(old);
    const f = await db.one(`UPDATE forums SET ${set.join(',')} WHERE id=$1 RETURNING *`, args); await ctx.audit(req, 'forum_update', 'forum', id, old, f); res.json(f);
  }));
  // bulk reorder / re-parent (drag & drop in the admin panel): { categories:[id,...], forums:[{id,category_id,parent_id,sort}] }
  r.put('/admin/structure/order', F, wrap(async (req, res) => {
    const b = req.body || {}, cats = Array.isArray(b.categories) ? b.categories : [], fs = Array.isArray(b.forums) ? b.forums : [];
    if (cats.length > 500 || fs.length > 2000) throw bad('Too many items');
    const all = await db.q('SELECT id,parent_id FROM forums'), pm = new Map(all.map(x => [x.id, x.parent_id])); for (const x of fs) pm.set(int(x.id, 'forum'), x.parent_id ? int(x.parent_id) : null); for (const id of pm.keys()) if (hasCycle(pm, id)) throw bad('That move would put a forum inside itself');
    await db.tx(async (tx) => {
      for (let i = 0; i < cats.length; i++) await tx.q('UPDATE categories SET sort=$2 WHERE id=$1', [int(cats[i], 'category'), i + 1]);
      for (const x of fs) await tx.q('UPDATE forums SET category_id=$2, parent_id=$3, sort=$4 WHERE id=$1 AND ($3::int IS NULL OR $3::int<>$1)', [int(x.id, 'forum'), int(x.category_id, 'category_id'), x.parent_id ? int(x.parent_id) : null, +x.sort || 0]);
    });
    await ctx.audit(req, 'structure_reorder', 'forum', null, null, { categories: cats.length, forums: fs.length }); res.json({ ok: true });
  }));
  r.delete('/admin/forums/:id', F, ctx.reauth, wrap(async (req, res) => { await db.q('DELETE FROM forums WHERE id=$1', [int(req.params.id)]); await ctx.audit(req, 'forum_delete', 'forum', req.params.id); res.json({ ok: true }); }));
  r.post('/admin/prefixes', F, wrap(async (req, res) => { const p = await db.one('INSERT INTO prefixes (name,color,text_color,advanced) VALUES ($1,$2,$3,$4) RETURNING *', [str(req.body.name, 'Name', { max: 30 }), req.body.color || '#ffd000', req.body.text_color || '#000000', !!req.body.advanced]); res.status(201).json(p); }));
  r.patch('/admin/prefixes/:id', F, wrap(async (req, res) => { const b = req.body, id = int(req.params.id); const p = await db.one('UPDATE prefixes SET name=COALESCE($2,name), color=COALESCE($3,color), text_color=COALESCE($4,text_color), advanced=COALESCE($5,advanced) WHERE id=$1 RETURNING *', [id, b.name ? str(b.name, 'Name', { max: 30 }) : null, b.color ?? null, b.text_color ?? null, typeof b.advanced === 'boolean' ? b.advanced : null]); if (!p) throw nf(); await ctx.audit(req, 'prefix_update', 'prefix', id, null, p); res.json(p); }));
  r.delete('/admin/prefixes/:id', F, wrap(async (req, res) => { await db.q('DELETE FROM prefixes WHERE id=$1', [int(req.params.id)]); res.json({ ok: true }); }));
  return r;
}
