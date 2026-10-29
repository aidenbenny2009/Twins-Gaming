import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs'; import os from 'node:os'; import path from 'node:path';
import { openDb } from '../src/db.js';
import { applySchema, seed } from '../src/seed.js';
import { createApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { hashPassword, totpAt } from '../src/security.js';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tg-'));
const cfg = { ...loadConfig({ NODE_ENV: 'test', SESSION_SECRET: 'x'.repeat(40), PUBLIC_URL: 'http://t.local', UPLOAD_DIR: tmp + '/up', BACKUP_DIR: tmp + '/bk' }), origins: ['http://t.local'], trustProxy: 1 };
const db = await openDb({ memory: true }); await applySchema(db); await seed(db); await db.q("UPDATE settings SET value='false' WHERE key='require_admin_2fa'");
const app = createApp(db, cfg); const srv = await new Promise(r => { const s = app.listen(0, () => r(s)); }); const base = `http://127.0.0.1:${srv.address().port}/api`;
test.after(async () => { srv.close(); await db.close(); });

class C {
  constructor(ip) { this.cookie = ''; this.csrf = ''; this.ip = ip || '10.0.0.' + Math.floor(Math.random() * 200 + 1); }
  async req(method, url, body, raw) {
    const h = { origin: 'http://t.local', 'x-forwarded-for': this.ip };
    if (this.cookie) h.cookie = this.cookie; if (this.csrf) h['x-csrf-token'] = this.csrf;
    let b; if (raw) { b = raw.buf; h['content-type'] = raw.type; } else if (body !== undefined) { b = JSON.stringify(body); h['content-type'] = 'application/json'; }
    const r = await fetch(base + url, { method, headers: h, body: b, signal: AbortSignal.timeout(8000) }).catch(e => { throw new Error(`${method} ${url}: ${e.message}`); }); const sc = r.headers.get('set-cookie'); if (sc) this.cookie = sc.split(';')[0];
    const t = await r.text(); let j; try { j = JSON.parse(t); } catch { j = t; } if (j?.csrf) this.csrf = j.csrf; return { s: r.status, j };
  }
  get(u) { return this.req('GET', u); } post(u, b) { return this.req('POST', u, b ?? {}); } patch(u, b) { return this.req('PATCH', u, b); } put(u, b) { return this.req('PUT', u, b); } del(u, b) { return this.req('DELETE', u, b ?? {}); }
}
const solve = async c => { const { j } = await c.get('/captcha'); const m = /(\d+) ([+−]) (\d+)/.exec(j.question); return { token: j.token, answer: m[2] === '+' ? +m[1] + +m[3] : +m[1] - +m[3] }; };
async function signup(name, ip) { const c = new C(ip); const r = await c.post('/auth/register', { username: name, email: name.toLowerCase() + '@ex.com', password: 'Str0ng-Pass-2026', captcha: await solve(c) }); assert.equal(r.s, 201, JSON.stringify(r.j)); return c; }
async function verifyAndLogin(c, name) {
  const mail = await db.one("SELECT body_html FROM outbox WHERE to_email=$1 AND template='verify' ORDER BY id DESC", [name.toLowerCase() + '@ex.com']); const tok = /token=([\w-]+)/.exec(mail.body_html)[1];
  assert.equal((await c.post('/auth/verify', { token: tok })).s, 200);
  const r = await c.post('/auth/login', { username: name, password: 'Str0ng-Pass-2026' }); assert.equal(r.s, 200, JSON.stringify(r.j)); return c;
}
const user = async (n, ip) => verifyAndLogin(await signup(n, ip), n);
let owner;
const forumId = async name => (await db.one('SELECT id FROM forums WHERE name=$1', [name])).id;

test('owner is unique and logs in with password', async () => {
  await db.q('INSERT INTO users (username,display_name,email,password_hash,is_owner,email_verified) VALUES ($1,$1,$2,$3,true,true)', ['Aiden', 'aiden@ex.com', await hashPassword('Owner-Pass-12345')]);
  await assert.rejects(db.q('INSERT INTO users (username,display_name,email,password_hash,is_owner) VALUES ($1,$1,$2,$3,true)', ['Other', 'o@ex.com', 'x']));
  owner = new C(); const r = await owner.post('/auth/login', { username: 'Aiden', password: 'Owner-Pass-12345' }); assert.equal(r.s, 200); assert.equal((await owner.get('/me')).j.user.perms[0], '*');
});
test('registration needs CAPTCHA, strong password, and email verification', async () => {
  const c = new C(); const base0 = { username: 'Zed', email: 'zed@ex.com', password: 'Str0ng-Pass-2026' };
  assert.equal((await c.post('/auth/register', { ...base0, captcha: { token: 'bad.bad.bad', answer: 1 } })).s, 400);
  assert.equal((await c.post('/auth/register', { ...base0, password: 'short', captcha: await solve(c) })).s, 400);
  const cap = await solve(c); assert.equal((await c.post('/auth/register', { ...base0, captcha: cap })).s, 201);
  assert.equal((await c.post('/auth/register', { ...base0, email: 'z2@ex.com', captcha: cap })).s, 400, 'captcha token is single-use');
  assert.equal((await c.post('/auth/login', { username: 'Zed', password: 'Str0ng-Pass-2026' })).s, 403, 'unverified cannot log in');
  await verifyAndLogin(c, 'Zed'); assert.equal((await c.get('/me')).j.user.username, 'Zed');
});
test('failed logins are recorded, CAPTCHA required, account locks, owner can unlock', async () => {
  const ip = '10.9.9.9', c = new C(ip); await user('Lock1', '10.1.1.1'); const u = new C(ip);
  for (let i = 0; i < 3; i++) assert.equal((await u.post('/auth/login', { username: 'Lock1', password: 'nope' + i })).s, 401);
  const r = await u.post('/auth/login', { username: 'Lock1', password: 'Str0ng-Pass-2026' }); assert.equal(r.s, 401); assert.ok(r.j.captcha, 'captcha demanded after repeated failures');
  const ok = await u.post('/auth/login', { username: 'Lock1', password: 'Str0ng-Pass-2026', captcha: await solve(u) }); assert.equal(ok.s, 200);
  const att = await owner.get('/admin/login-attempts?failed=1'); assert.ok(att.j.length >= 3);
  const L = new C('10.2.2.2'); await db.q("UPDATE settings SET value='2' WHERE key='captcha_on_login_after'"); await db.q("UPDATE settings SET value='3' WHERE key='login_max_failures'"); await new Promise(r => setTimeout(r, 3100));
  for (let i = 0; i < 3; i++) await L.post('/auth/login', { username: 'Lock1', password: 'x' + i, captcha: await solve(L) });
  assert.equal((await L.post('/auth/login', { username: 'Lock1', password: 'Str0ng-Pass-2026', captcha: await solve(L) })).s, 423);
  const id = (await db.one("SELECT id FROM users WHERE username='Lock1'")).id; assert.equal((await owner.post(`/admin/users/${id}/unlock`)).s, 200);
  await db.q("UPDATE settings SET value='5' WHERE key='login_max_failures'"); await db.q("UPDATE settings SET value='3' WHERE key='captcha_on_login_after'"); await new Promise(r => setTimeout(r, 3100));
});
test('2FA: setup, enable, login requires code, recovery code works once', async () => {
  const c = await user('Tfa'); const s = (await c.post('/2fa/setup')).j; assert.ok(s.secret);
  const en = await c.post('/2fa/enable', { code: totpAt(s.secret) }); assert.equal(en.s, 200); assert.equal(en.j.recovery_codes.length, 8);
  const d = new C(); const r1 = await d.post('/auth/login', { username: 'Tfa', password: 'Str0ng-Pass-2026' }); assert.equal(r1.s, 401); assert.ok(r1.j.needs_2fa);
  assert.equal((await d.post('/auth/login', { username: 'Tfa', password: 'Str0ng-Pass-2026', totp: '000000' })).s, 401);
  assert.equal((await d.post('/auth/login', { username: 'Tfa', password: 'Str0ng-Pass-2026', totp: totpAt(s.secret) })).s, 200);
  const e = new C(); assert.equal((await e.post('/auth/login', { username: 'Tfa', password: 'Str0ng-Pass-2026', totp: en.j.recovery_codes[0] })).s, 200);
  assert.equal((await new C().post('/auth/login', { username: 'Tfa', password: 'Str0ng-Pass-2026', totp: en.j.recovery_codes[0] })).s, 401, 'recovery code is single-use');
});
test('password reset flow ends all sessions', async () => {
  const c = await user('Rst'); await c.post('/auth/forgot', { email: 'rst@ex.com' }); assert.equal((await c.post('/auth/forgot', { email: 'nobody@ex.com' })).s, 200);
  const m = await db.one("SELECT body_html FROM outbox WHERE template='reset' ORDER BY id DESC"); const tok = /token=([\w-]+)/.exec(m.body_html)[1];
  assert.equal((await new C().post('/auth/reset', { token: tok, password: 'NewStr0ng-Pass-2026' })).s, 200); assert.equal((await c.get('/me')).j.user, null);
  assert.equal((await new C().post('/auth/login', { username: 'Rst', password: 'NewStr0ng-Pass-2026' })).s, 200);
});
test('CSRF: token required for logged-in writes, bad origin blocked', async () => {
  const c = await user('Csrf'); const f = await forumId('General Discussion'); const saved = c.csrf; c.csrf = '';
  assert.equal((await c.post('/threads', { forum_id: f, title: 'Hello there', body: 'x' })).s, 403); c.csrf = saved;
  const r = await fetch(base + '/auth/logout', { method: 'POST', headers: { origin: 'http://evil.example', cookie: c.cookie, 'x-csrf-token': c.csrf } }); assert.equal(r.status, 403);
});

let T, PID, mod, alice, bob;
test('threads, replies, quotes, mentions, edit history, reactions, bookmarks, solved', async () => {
  alice = await user('Alice'); bob = await user('Bob'); const f = await forumId('General Discussion');
  const t = await alice.post('/threads', { forum_id: f, title: 'First thread', body: 'Hello @Bob welcome' }); assert.equal(t.s, 201); T = t.j.id;
  assert.equal((await bob.get('/notifications')).j.items.some(n => n.type === 'mention'), true, 'mention notified');
  const first = (await bob.get(`/threads/${T}`)).j.posts[0]; PID = first.id;
  const rep = await bob.post(`/threads/${T}/posts`, { body: 'Thanks!', quote_post_id: PID }); assert.equal(rep.s, 201);
  assert.equal((await alice.get('/notifications')).j.items.some(n => n.type === 'quote'), true);
  const view = (await bob.get(`/threads/${T}`)).j; assert.equal(view.posts[1].quote.by, 'Alice'); assert.equal(view.thread.reply_count, 1);
  assert.equal((await alice.patch(`/posts/${PID}`, { body: 'Hello @Bob (edited)' })).s, 200);
  const rv = await alice.get(`/posts/${PID}/revisions`); assert.equal(rv.j.revisions[0].body, 'Hello @Bob welcome'); assert.equal((await bob.get(`/posts/${PID}/revisions`)).s, 403);
  assert.equal((await bob.post(`/posts/${PID}/react`, { type: 'like' })).s, 200); assert.equal((await bob.post(`/posts/${PID}/react`, { type: 'bogus' })).s, 400); assert.equal((await alice.post(`/posts/${PID}/react`, { type: 'like' })).s, 400);
  assert.equal((await bob.post(`/threads/${T}/bookmark`)).s, 200); assert.equal((await bob.get('/me/bookmarks')).j.length, 1);
  assert.equal((await bob.post(`/threads/${T}/mod`, { action: 'solve' })).s, 403, 'only author/mods can solve'); assert.equal((await alice.post(`/threads/${T}/mod`, { action: 'solve' })).s, 200);
  assert.equal((await alice.post(`/threads/${T}/mod`, { action: 'lock' })).s, 403, 'members cannot lock');
});
test('search finds threads and posts', async () => {
  assert.equal((await bob.get('/search?q=first')).j[0].title, 'First thread'); assert.ok((await bob.get('/search?q=edited&scope=posts')).j.length >= 1);
});
test('staff permissions are enforced per role; move, merge, split, bulk', async () => {
  mod = await user('Mod1'); const id = (await db.one("SELECT id FROM users WHERE username='Mod1'")).id, role = (await db.one("SELECT id FROM roles WHERE name='Moderator'")).id;
  assert.equal((await mod.put(`/admin/users/${id}/roles`, { role_ids: [role] })).s, 403, 'non-owner cannot grant roles'); assert.equal((await owner.put(`/admin/users/${id}/roles`, { role_ids: [role] })).s, 200);
  const f = await forumId('General Discussion'), g = await forumId('Gaming');
  const t2 = (await alice.post('/threads', { forum_id: f, title: 'Second thread', body: 'one' })).j.id; await bob.post(`/threads/${t2}/posts`, { body: 'two' }); await alice.post(`/threads/${t2}/posts`, { body: 'three' });
  assert.equal((await mod.post(`/threads/${t2}/move`, {})).s, 404); // not a route -> must use mod endpoint
  assert.equal((await mod.post(`/threads/${t2}/mod`, { action: 'move', forum_id: g })).s, 200); assert.equal((await db.one('SELECT forum_id FROM threads WHERE id=$1', [t2])).forum_id, g);
  assert.equal((await mod.post(`/threads/${t2}/mod`, { action: 'feature' })).s, 403, 'moderator lacks FEATURE_THREAD');
  const posts = (await mod.get(`/threads/${t2}`)).j.posts; const sp = await mod.post(`/threads/${t2}/split`, { post_ids: [posts[2].id], title: 'Split off' }); assert.equal(sp.s, 200, JSON.stringify(sp.j));
  assert.equal((await db.one('SELECT reply_count FROM threads WHERE id=$1', [t2])).reply_count, 1);
  const mg = await mod.post(`/threads/${sp.j.id}/merge`, { into: t2 }); assert.equal(mg.s, 200); assert.equal((await db.one('SELECT reply_count FROM threads WHERE id=$1', [t2])).reply_count, 2);
  assert.equal((await db.one('SELECT count(*)::int n FROM threads WHERE id=$1', [sp.j.id])).n, 0);
  const bulk = await mod.post('/mod/bulk', { thread_ids: [T, t2], action: 'pin' }); assert.ok(bulk.j.results.every(x => x.ok)); assert.equal((await alice.post('/mod/bulk', { thread_ids: [T], action: 'pin' })).s, 403);
  assert.ok((await owner.get('/admin/audit?action=thread_')).j.some(a => a.action === 'thread_merge'));
  assert.equal((await mod.get('/admin/security')).s, 403, 'moderator has no VIEW_SECURITY'); assert.equal((await mod.get('/admin/ip?ip=1.1.1.1')).s, 403);
});
test('post deletion is soft, visible to staff only; first post protected', async () => {
  const r = await bob.post(`/threads/${T}/posts`, { body: 'to be removed' }); const pid = r.j.id; assert.equal((await bob.del(`/posts/${pid}`)).s, 200);
  assert.equal((await alice.get(`/threads/${T}`)).j.posts.some(p => p.id === pid), false); assert.equal((await mod.get(`/threads/${T}`)).j.posts.find(p => p.id === pid).body, '[removed]'.length ? (await mod.get(`/threads/${T}`)).j.posts.find(p => p.id === pid).body : '');
  assert.equal((await alice.del(`/posts/${PID}`)).s, 400);
});
test('anti-spam: duplicates rejected, flooding auto-timeouts and is audited', async () => {
  const f = await forumId('General Discussion'), s = await user('Spammy'); assert.equal((await s.post('/threads', { forum_id: f, title: 'Spam thread', body: 'buy now' })).s, 201);
  assert.equal((await s.post('/threads', { forum_id: f, title: 'Spam thread 2', body: 'buy now' })).s, 429, 'duplicate');
  await db.q("UPDATE settings SET value='3' WHERE key='flood_max_per_minute'"); await new Promise(r => setTimeout(r, 3100)); let hit = 0;
  for (let i = 0; i < 6; i++) { const r = await s.post(`/threads/${T}/posts`, { body: 'unique ' + i }); if (r.s === 429) hit++; }
  assert.ok(hit >= 1); const r = await s.post(`/threads/${T}/posts`, { body: 'after mute' }); assert.equal(r.s, 403, 'timed out');
  assert.ok((await db.one("SELECT count(*)::int n FROM audit_logs WHERE action='auto_punish'")).n >= 1); await db.q("UPDATE settings SET value='6' WHERE key='flood_max_per_minute'");
});
test('sanctions: warn/timeout/ban with permissions, owner protected', async () => {
  const c = await user('Naughty'), id = (await db.one("SELECT id FROM users WHERE username='Naughty'")).id, oid = (await db.one("SELECT id FROM users WHERE is_owner")).id;
  assert.equal((await alice.post(`/staff/users/${id}/sanction`, { type: 'warn', reason: 'abuse' })).s, 403);
  assert.equal((await mod.post(`/staff/users/${id}/sanction`, { type: 'warn', reason: 'be nice' })).s, 201); assert.equal((await mod.post(`/staff/users/${id}/sanction`, { type: 'ban', reason: 'x1x' })).s, 403, 'mod cannot ban');
  assert.equal((await owner.post(`/staff/users/${oid}/sanction`, { type: 'ban', reason: 'self' })).s, 400);
  assert.equal((await owner.post(`/staff/users/${id}/sanction`, { type: 'ban', reason: 'cheating', minutes: 60 })).s, 201);
  const f = await forumId('General Discussion'); assert.equal((await c.post('/threads', { forum_id: f, title: 'banned post', body: 'hi' })).s, 403);
  assert.equal((await owner.post(`/staff/users/${id}/sanction`, { type: 'unban', reason: 'appeal accepted' })).s, 201); assert.equal((await c.post('/threads', { forum_id: f, title: 'back again', body: 'hi' })).s, 201);
  assert.equal((await mod.del(`/admin/users/${oid}`)).s, 403); assert.equal((await owner.del(`/admin/users/${oid}`)).s, 400);
});
test('private messages respect privacy and blocks', async () => {
  assert.equal((await alice.post('/conversations', { to: 'Bob', body: 'hi bob' })).s, 201);
  await bob.patch('/me/profile', { prefs: { dm: 'nobody' } }); assert.equal((await alice.post('/conversations', { to: 'Bob', body: 'again' })).s, 403);
  await bob.patch('/me/profile', { prefs: { dm: 'everyone' } }); await bob.post('/users/Alice/block'); assert.equal((await alice.post('/conversations', { to: 'Bob', body: 'blocked?' })).s, 403);
  const inbox = (await bob.get('/conversations')).j; assert.equal(inbox[0].with_user, 'Alice'); assert.equal(inbox[0].unread, 1);
});
test('uploads verify image bytes and size limits', async () => {
  const png = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(100)]);
  const up = await alice.req('POST', '/uploads?title=pic', undefined, { buf: png, type: 'image/png' }); assert.equal(up.s, 201); assert.match(up.j.url, /\.png$/);
  assert.equal((await alice.req('POST', '/uploads', undefined, { buf: Buffer.from('<script>alert(1)</script>'), type: 'image/png' })).s, 400, 'fake image rejected');
  await owner.put('/admin/settings/max_upload_mb', { value: 1 }); assert.equal((await alice.req('POST', '/uploads', undefined, { buf: Buffer.concat([png, Buffer.alloc(1.5e6)]), type: 'image/png' })).s, 413); await owner.put('/admin/settings/max_upload_mb', { value: 12 });
});
test('owner-only areas and role editing', async () => {
  assert.equal((await alice.get('/admin/users')).s, 403); assert.equal((await mod.put('/admin/settings/registration_open', { value: false })).s, 403);
  const r = (await owner.post('/admin/roles', { name: 'Helper', color: '#00ffaa', is_staff: true, perms: ['HANDLE_REPORTS', 'VIEW_FORUM'] })).j; assert.ok(r.id); assert.equal((await mod.post('/admin/roles', { name: 'X' })).s, 403);
  assert.equal((await owner.patch(`/admin/roles/${r.id}`, { perms: ['NOT_A_PERM'] })).s, 400);
  assert.equal((await owner.put('/admin/settings/theme', { value: { default: 'light', accent: '#ffd000', custom_css: 'body{x:y}' } })).s, 200);
});
test('rules revision history visibility is decided by the Owner', async () => {
  const sec = (await owner.post('/admin/rule-sections', { name: 'General' })).j; const rl = (await owner.post('/admin/rules', { section_id: sec.id, title: 'Be kind', body: 'v1', status: 'published' })).j; await owner.patch(`/admin/rules/${rl.id}`, { body: 'v2' });
  assert.equal((await alice.get(`/rules/${rl.id}/revisions`)).s, 403); const aid = (await db.one("SELECT id FROM users WHERE username='Alice'")).id; await owner.put(`/admin/revision-viewers/${aid}`);
  assert.equal((await alice.get(`/rules/${rl.id}/revisions`)).j.length, 2); assert.equal((await alice.get('/rules')).j.sections[0].rules[0].title, 'Be kind');
});
test('IP search, security dashboard, analytics, export need re-auth', async () => {
  const ip = (await db.one("SELECT reg_ip FROM users WHERE username='Alice'")).reg_ip; assert.ok((await owner.get(`/admin/ip?ip=${ip}`)).j.users.some(u => u.username === 'Alice'));
  assert.ok((await owner.get('/admin/security')).j.failed_24h >= 3); await new C().post('/track', { path: '/forums' }); assert.ok((await owner.get('/admin/analytics')).j.top_pages.length >= 1);
  await db.q('UPDATE sessions SET reauth_at = now() - interval \'1 hour\' WHERE user_id=(SELECT id FROM users WHERE is_owner)');
  const ex = await owner.get('/admin/export/users'); assert.equal(ex.s, 401); assert.ok(ex.j.reauth);
  assert.equal((await owner.post('/auth/reauth', { password: 'wrong' })).s, 401); assert.equal((await owner.post('/auth/reauth', { password: 'Owner-Pass-12345' })).s, 200);
  const ok = await owner.get('/admin/export/users'); assert.equal(ok.s, 200); assert.ok(!/password_hash/.test(ok.j));
});
test('backup then restore returns the database to the saved state', async () => {
  const b = await owner.post('/admin/backups'); assert.equal(b.s, 201, JSON.stringify(b.j)); const before = (await db.one('SELECT count(*)::int n FROM users')).n;
  await user('Late'); assert.equal((await db.one('SELECT count(*)::int n FROM users')).n, before + 1);
  assert.equal((await owner.post(`/admin/backups/${b.j.id}/restore`, { confirm: 'no' })).s, 400);
  const r = await owner.post(`/admin/backups/${b.j.id}/restore`, { confirm: 'RESTORE' }); assert.equal(r.s, 200, JSON.stringify(r.j));
  assert.equal((await db.one('SELECT count(*)::int n FROM users')).n, before); assert.equal((await owner.get('/me')).j.user, null, 'sessions cleared');
  const again = new C(); assert.equal((await again.post('/auth/login', { username: 'Aiden', password: 'Owner-Pass-12345' })).s, 200);
  assert.equal((await again.post('/threads', { forum_id: await forumId('General Discussion'), title: 'after restore', body: 'identity sequences work' })).s, 201);
});
test('maintenance mode blocks members but not the Owner', async () => {
  const o = new C(); await o.post('/auth/login', { username: 'Aiden', password: 'Owner-Pass-12345' }); await o.post('/admin/maintenance', { on: true, message: 'brb' });
  assert.equal((await new C().get('/forums')).s, 503); assert.equal((await o.get('/forums')).s, 200); await o.post('/admin/maintenance', { on: false });
});
test('username change needs staff approval; reactions list shows who reacted', async () => {
  const a = await user('NameChanger', '10.9.0.1'), b = await user('Reactor', '10.9.0.2');
  assert.equal((await a.post('/me/username-change', { username: 'bad name' })).s, 400);
  assert.equal((await a.post('/me/username-change', { username: 'Reactor' })).s, 409, 'taken');
  assert.equal((await a.post('/me/username-change', { username: 'FreshName' })).s, 201);
  assert.equal((await a.post('/me/username-change', { username: 'Other_One' })).s, 409, 'only one pending');
  assert.equal((await a.get('/me')).j.user.username, 'NameChanger', 'not changed until approved');
  assert.equal((await b.get('/admin/name-changes')).s, 403, 'members cannot review');
  const o = new C(); await o.post('/auth/login', { username: 'Aiden', password: 'Owner-Pass-12345' });
  const list = (await o.get('/admin/name-changes')).j; const req = list.find(x => x.new_name === 'FreshName'); assert.equal(req.status, 'pending');
  assert.equal((await o.post('/admin/name-changes/' + req.id, { approve: true })).s, 200);
  assert.equal((await a.get('/me')).j.user.username, 'FreshName');
  assert.equal((await o.post('/admin/name-changes/' + req.id, { approve: true })).s, 404, 'already decided');
  const fid = await forumId('General Discussion'); const t = (await a.post('/threads', { forum_id: fid, title: 'React to me', body: 'hello there' })).j;
  const post = (await db.one('SELECT id FROM posts WHERE thread_id=$1', [t.id])).id;
  assert.equal((await b.post('/posts/' + post + '/react', { type: 'angry' })).s, 200);
  assert.equal((await b.post('/posts/' + post + '/react', { type: 'dislike' })).s, 200);
  const rl = (await a.get('/posts/' + post + '/reactions')).j; assert.equal(rl.length, 1); assert.equal(rl[0].type, 'dislike'); assert.equal(rl[0].username, 'Reactor');
});
test('staff list is visible to staff only and includes the owner', async () => {
  const m = await user('PlainMember', '10.9.1.1'); assert.equal((await m.get('/admin/staff')).s, 403);
  const o = new C(); await o.post('/auth/login', { username: 'Aiden', password: 'Owner-Pass-12345' });
  const sj = (await o.get('/admin/staff')).j; assert.equal(sj.target, 120); const l = sj.rows; assert.equal(typeof l[0].minutes_today, 'number'); assert.ok(l.find(x => x.username === 'Aiden' && x.is_owner)); assert.equal(typeof (await o.get('/admin/dashboard')).j.banned, 'number');
});

test('staff must enable 2FA when require_admin_2fa is on', async () => {
  await db.q("UPDATE settings SET value='true' WHERE key='require_admin_2fa'"); await new Promise(r => setTimeout(r, 3100));
  const o = new C(); await o.post('/auth/login', { username: 'Aiden', password: 'Owner-Pass-12345' });
  const r = await o.get('/admin/staff'); assert.equal(r.s, 403); assert.equal(r.j.need2fa, true);
  const m = await user('NoStaff2fa', '10.9.2.2'); assert.equal((await m.get('/me')).s, 200);
  await db.q("UPDATE settings SET value='false' WHERE key='require_admin_2fa'"); await new Promise(r => setTimeout(r, 3100));
  assert.equal((await o.get('/admin/staff')).s, 200);
});

test('member posts list, name history and online flag', async () => {
  const a = await user('Histo', '10.9.3.3'); const f = await forumId('General Discussion').catch(() => null);
  const r = await a.get('/users/Histo'); assert.equal(r.s, 200); assert.ok(Array.isArray(r.j.name_history)); assert.equal(typeof r.j.online, 'boolean');
  const p = await a.get('/users/Histo/posts'); assert.equal(p.s, 200); assert.ok(Array.isArray(p.j));
  const o = new C(); await o.post('/auth/login', { username: 'Aiden', password: 'Owner-Pass-12345' });
  const id = (await db.one("SELECT id FROM users WHERE username='Histo'")).id; const rel = await o.get('/admin/users/' + id + '/related'); assert.equal(rel.s, 200); assert.ok(Array.isArray(rel.j));
});

test('thread title / prefix can be edited by staff and the author', async () => {
  const a = await user('EditAuth', '10.9.4.4'); const f = await forumId('General Discussion').catch(async () => (await db.one('SELECT id FROM forums LIMIT 1')).id);
  const th = await a.post('/threads', { forum_id: f, title: 'before', body: 'hello there' }); assert.equal(th.s, 201, JSON.stringify(th.j));
  assert.equal((await a.patch('/threads/' + th.j.id, { title: 'after' })).s, 200);
  const o = new C(); await o.post('/auth/login', { username: 'Aiden', password: 'Owner-Pass-12345' });
  assert.equal((await o.patch('/threads/' + th.j.id, { title: 'by staff' })).s, 200);
  assert.equal((await db.one('SELECT title FROM threads WHERE id=$1', [th.j.id])).title, 'by staff');
  const b = await user('EditOther', '10.9.4.5'); assert.equal((await b.patch('/threads/' + th.j.id, { title: 'hack' })).s, 403);
});

test('rss feed is public and rss_url is a setting', async () => {
  const r = await fetch(base.replace('/api', '') + '/forums/-/index.rss'); assert.equal(r.status, 200); assert.match(await r.text(), /<rss version="2.0">/);
  const c = new C(); assert.equal(typeof (await c.get('/config')).j.rss_url, 'string');
});

test('rss feed is public and rss_url is a setting', async () => {
  const r = await fetch(base.replace('/api', '') + '/forums/-/index.rss'); assert.equal(r.status, 200); assert.match(await r.text(), /<rss version="2.0">/);
  const c = new C(); assert.equal(typeof (await c.get('/config')).j.rss_url, 'string');
});

test('Sign in with Google creates/links an account and uses the Google photo', async () => {
  cfg.googleClientId = 'cid-123'; cfg.googleVerify = async c => JSON.parse(c);
  const cred = o => JSON.stringify({ aud: 'cid-123', sub: 'sub-1', email: 'gperson@gmail.com', email_verified: 'true', picture: 'https://lh3.googleusercontent.com/a/pic', ...o });
  const c = new C(); assert.equal((await c.post('/auth/google', { credential: cred({ aud: 'other' }) })).s, 401);
  assert.equal((await c.post('/auth/google', { credential: cred({ email_verified: 'false' }) })).s, 401);
  const r = await c.post('/auth/google', { credential: cred() }); assert.equal(r.s, 200, JSON.stringify(r.j));
  const me = (await c.get('/me')).j.user; assert.equal(me.username, 'gperson'); assert.equal(me.avatar_url, 'https://lh3.googleusercontent.com/a/pic');
  const c2 = new C(); assert.equal((await c2.post('/auth/google', { credential: cred() })).s, 200); // same account again
  assert.equal((await new C().get('/config')).j.google_client_id, 'cid-123');
  cfg.googleClientId = ''; assert.equal((await new C().post('/auth/google', { credential: cred() })).s, 404);
});

test('structure: nested forums, link/page rows, reorder, role/permission gates', async () => {
  const o = await user('StructAdmin');
  const sid = (await db.one("SELECT id FROM users WHERE username='StructAdmin'")).id; const rid = (await db.one('INSERT INTO roles (name,color,is_staff) VALUES ($1,$2,true) RETURNING id', ['StructRole', '#fff'])).id;
  await db.q("INSERT INTO role_permissions (role_id,perm_key) VALUES ($1,'MANAGE_FORUMS'),($1,'VIEW_ADMIN_PANEL'),($1,'ADMIN_TAKE_ACTION')", [rid]); await db.q('INSERT INTO user_roles (user_id,role_id) VALUES ($1,$2)', [sid, rid]);
  const cat = (await o.post('/admin/categories', { name: 'Struct cat' })).j;
  const a = (await o.post('/admin/forums', { category_id: cat.id, name: 'Top A' })).j, b = (await o.post('/admin/forums', { category_id: cat.id, parent_id: a.id, name: 'Sub B' })).j;
  const lr = await o.post('/admin/forums', { category_id: cat.id, name: 'Discord row', link_url: 'https://discord.gg/x', page_route: null }); const l = lr.j; assert.equal(lr.s, 201, JSON.stringify(lr.j)); assert.equal(l.link_url, 'https://discord.gg/x');
  const idx = (await new C().get('/forums')).j; const f = idx.categories.find(c => c.id === cat.id).forums; assert.equal(f.find(x => x.id === b.id).parent_id, a.id);
  const cat2 = (await o.post('/admin/categories', { name: 'Struct cat 2' })).j;
  assert.equal((await o.put('/admin/structure/order', { categories: [cat2.id, cat.id], forums: [{ id: b.id, category_id: cat2.id, parent_id: null, sort: 1 }] })).s, 200);
  assert.equal((await db.one('SELECT category_id FROM forums WHERE id=$1', [b.id])).category_id, cat2.id);
  assert.ok((await db.one('SELECT sort FROM categories WHERE id=$1', [cat2.id])).sort < (await db.one('SELECT sort FROM categories WHERE id=$1', [cat.id])).sort);
  const m = await user('StructMem'); let n = 0; const post = fid => m.post('/threads', { forum_id: fid, title: 'Hello there ' + (++n), body: 'body text number ' + n + ' ' + Math.random() });
  assert.equal((await post(b.id)).s, 201);
  await o.patch('/admin/forums/' + b.id, { thread_perm: 'NO_ONE' }); assert.equal((await post(b.id)).s, 403);
  await o.patch('/admin/forums/' + b.id, { thread_perm: 'CREATE_THREAD', thread_roles: ['no-such-role'] }); assert.equal((await post(b.id)).s, 403);
  const role = (await db.one("SELECT id FROM roles WHERE name='Member' OR is_default LIMIT 1"))?.id;
  if (role !== undefined) { const pr = await o.patch('/admin/forums/' + b.id, { thread_perm: 'CREATE_THREAD', thread_roles: [role] });  const pp = await post(b.id); assert.equal(pp.s, 201, JSON.stringify(pp.j)); }
  await o.patch('/admin/forums/' + b.id, { thread_roles: [], thread_perm: 'EDIT_ANY_POST' }); assert.equal((await post(b.id)).s, 403);
  // hardening: no cycles, no javascript: links, no made-up permissions
  assert.equal((await o.patch('/admin/forums/' + b.id, { category_id: cat.id, parent_id: a.id })).s, 200);
  assert.equal((await o.patch('/admin/forums/' + a.id, { parent_id: b.id })).s, 400);
  assert.equal((await o.post('/admin/forums', { category_id: cat.id, name: 'Bad', link_url: 'javascript:alert(1)' })).s, 400);
  assert.equal((await o.patch('/admin/forums/' + a.id, { thread_perm: 'DROP_TABLE' })).s, 400);
  assert.equal((await o.put('/admin/structure/order', { categories: [], forums: [{ id: a.id, category_id: cat.id, parent_id: l.id, sort: 1 }, { id: l.id, category_id: cat.id, parent_id: a.id, sort: 2 }] })).s, 400);
});

test('crawlable pages, sitemap and robots (public forums only, everything escaped)', async () => {
  const m = await user('SeoMember'); const gf = await forumId('General Discussion');
  const tr = await m.post('/threads', { forum_id: gf, title: 'Seo <b>title</b> thread', body: 'Hello [b]world[/b] <script>alert(1)</script> text' }); assert.equal(tr.s, 201, JSON.stringify(tr.j));
  const root = base.replace('/api', ''), tid = tr.j.id ?? tr.j.thread?.id;
  const r = await fetch(`${root}/t/${tid}`, { headers: { 'user-agent': 'Googlebot' } }); assert.equal(r.status, 200); const h = await r.text();
  assert.match(h, /<link rel="canonical" href="http:\/\/t\.local\/t\/\d+">/); assert.ok(!h.includes('<script>alert(1)</script>')); assert.ok(!h.includes('<b>title</b>')); assert.match(h, /Hello world/); assert.ok(!h.includes('location.replace'));
  assert.match(await (await fetch(`${root}/t/${tid}`, { headers: { 'user-agent': 'Mozilla/5.0' } })).text(), /location\.replace/);
  const sm = await (await fetch(root + '/sitemap.xml')).text(); assert.ok(sm.includes(`/t/${tid}`));
  assert.match(await (await fetch(root + '/robots.txt')).text(), /Sitemap: http:\/\/t\.local\/sitemap\.xml/);
  await db.q('UPDATE forums SET hidden=true WHERE id=$1', [gf]); assert.equal((await fetch(`${root}/t/${tid}`)).status, 404); assert.ok(!(await (await fetch(root + '/sitemap.xml')).text()).includes(`/t/${tid}`)); await db.q('UPDATE forums SET hidden=false WHERE id=$1', [gf]);
  assert.equal((await fetch(`${root}/t/abc`)).status, 404);
});

test('sections: hide, members-only/staff-only, colour validation, collapsed flag', async () => {
  const o = await user('SecAdmin'); const sid = (await db.one("SELECT id FROM users WHERE username='SecAdmin'")).id;
  const rid = (await db.one('INSERT INTO roles (name,color,is_staff) VALUES ($1,$2,true) RETURNING id', ['SecRole', '#fff'])).id;
  await db.q("INSERT INTO role_permissions (role_id,perm_key) VALUES ($1,'MANAGE_FORUMS'),($1,'VIEW_ADMIN_PANEL'),($1,'ADMIN_TAKE_ACTION')", [rid]); await db.q('INSERT INTO user_roles (user_id,role_id) VALUES ($1,$2)', [sid, rid]);
  const cat = (await o.post('/admin/categories', { name: 'Sec cat' })).j, names = async (c) => (await (await fetch(base + '/forums', c)).json()).categories.map(x => x.name);
  assert.ok((await names()).includes('Sec cat'));
  assert.equal((await o.patch('/admin/categories/' + cat.id, { visibility: 'members', color: '#d4145a', collapsed: true })).s, 200);
  assert.ok(!(await names()).includes('Sec cat'), 'members-only hidden from guests');
  assert.equal((await o.patch('/admin/categories/' + cat.id, { color: 'red' })).s, 400);
  assert.equal((await o.patch('/admin/categories/' + cat.id, { visibility: 'nope' })).s, 400);
  const c1 = (await o.get('/forums')).j.categories.find(x => x.name === 'Sec cat'); assert.ok(c1); assert.equal(c1.visibility, 'members'); assert.equal(c1.color, '#d4145a'); assert.equal(c1.collapsed, true);
  await o.patch('/admin/categories/' + cat.id, { visibility: 'all', hidden: true }); assert.ok(!(await names()).includes('Sec cat'), 'hidden section not shown to guests');
  assert.ok((await o.get('/forums')).j.categories.some(x => x.name === 'Sec cat'), 'staff still see hidden section');
});

test('warning: staff only, expires in a week, auto-sends a "Warning" conversation', async () => {
  const st = await user('WarnStaff'), sid = (await db.one("SELECT id FROM users WHERE username='WarnStaff'")).id, tg = await user('WarnTarget'), tid = (await db.one("SELECT id FROM users WHERE username='WarnTarget'")).id;
  assert.equal((await tg.post('/staff/users/' + sid + '/sanction', { type: 'warn', reason: 'nope' })).s, 403, 'members cannot warn');
  const rid = (await db.one('INSERT INTO roles (name,color,is_staff) VALUES ($1,$2,true) RETURNING id', ['WarnRole', '#fff'])).id;
  await db.q("INSERT INTO role_permissions (role_id,perm_key) VALUES ($1,'WARN_USER'),($1,'VIEW_ADMIN_PANEL'),($1,'ADMIN_TAKE_ACTION')", [rid]); await db.q('INSERT INTO user_roles (user_id,role_id) VALUES ($1,$2)', [sid, rid]);
  const r = await st.post('/staff/users/' + tid + '/sanction', { type: 'warn', reason: 'Offtop', comment: 'Please stay on topic', subject: 'Leader for Hospital', message: 'Best of luck' }); assert.equal(r.s, 201, JSON.stringify(r.j));
  const w = await db.one("SELECT expires_at FROM sanctions WHERE user_id=$1 AND type='warn'", [tid]); const days = (new Date(w.expires_at) - Date.now()) / 86400000; assert.ok(days > 6.9 && days < 7.1);
  const cv = (await tg.get('/conversations')).j.find(c => c.title === 'Warning'); assert.ok(cv, 'warning conversation exists'); assert.equal(cv.with_user, 'WarnStaff');
  const ms = (await tg.get('/conversations/' + cv.id + '/messages')).j; assert.match(ms[0].body, /you received a warning from the moderator: \[b\]WarnStaff\[\/b\]/); assert.match(ms[0].body, /Reason: Offtop/); assert.match(ms[0].body, /Subject: Leader for Hospital/); assert.match(ms[0].body, /removed in 1 week/); assert.match(ms[0].body, /3 warnings/);
});

test('support section is gone: tickets, appeals and applications no longer exist', async () => {
  for (const u of ['/tickets', '/appeals', '/applications', '/application-types']) assert.equal((await alice.get(u)).s, 404, u);
  assert.equal((await db.one("SELECT count(*)::int n FROM permissions WHERE key IN ('HANDLE_TICKETS','CREATE_TICKET')")).n, 0);
});
test('admin panel: VIEW_ADMIN_PANEL is read-only, ADMIN_TAKE_ACTION allows changes', async () => {
  owner = new C(); assert.equal((await owner.post('/auth/login', { username: 'Aiden', password: 'Owner-Pass-12345' })).s, 200);
  const v = await user('Viewer'), id = (await db.one("SELECT id FROM users WHERE username='Viewer'")).id;
  const role = (await owner.post('/admin/roles', { name: 'Observer', color: '#88aaff', is_staff: true, perms: ['VIEW_ADMIN_PANEL', 'MANAGE_USERS', 'VIEW_AUDIT', 'WARN_USER', 'VIEW_FORUM'] })).j;
  const rr = await owner.put(`/admin/users/${id}/roles`, { role_ids: [role.id] }); assert.equal(rr.s, 200, JSON.stringify(rr.j));
  assert.equal((await v.get('/admin/users')).s, 200, 'can look');
  assert.equal((await v.patch(`/admin/users/${(await db.one("SELECT id FROM users WHERE username='Bob'")).id}`, { display_name: 'Bobby' })).s, 403, 'cannot act');
  const t = (await db.one("SELECT id FROM users WHERE username='Bob'")).id; assert.equal((await v.post(`/staff/users/${t}/sanction`, { type: 'warn', reason: 'testing view' })).s, 403);
  assert.equal((await owner.patch(`/admin/roles/${role.id}`, { perms: ['VIEW_ADMIN_PANEL', 'ADMIN_TAKE_ACTION', 'MANAGE_USERS', 'WARN_USER', 'VIEW_FORUM'] })).s, 200);
  assert.equal((await v.post(`/staff/users/${t}/sanction`, { type: 'warn', reason: 'now allowed' })).s, 201);
  await owner.patch(`/admin/roles/${role.id}`, { perms: ['MANAGE_USERS', 'VIEW_FORUM'] }); assert.equal((await v.get('/admin/users')).s, 403, 'no view permission, no panel');
});
test('hide "Post thread": globally, per section and per forum (inherited by sub-forums)', async () => {
  const f = await forumId('General Discussion'), c = await user('Poster');
  assert.equal((await c.post('/threads', { forum_id: f, title: 'allowed thread', body: 'one' })).s, 201);
  const cat = (await db.one('SELECT category_id FROM forums WHERE id=$1', [f])).category_id;
  assert.equal((await owner.patch(`/admin/categories/${cat}`, { no_threads: true })).s, 200);
  assert.equal((await c.post('/threads', { forum_id: f, title: 'blocked by section', body: 'two' })).s, 403);
  await owner.patch(`/admin/categories/${cat}`, { no_threads: false });
  await owner.patch(`/admin/forums/${f}`, { thread_perm: 'NO_ONE' });
  assert.equal((await c.post('/threads', { forum_id: f, title: 'blocked by forum', body: 'three' })).s, 403);
  assert.equal((await owner.post('/threads', { forum_id: f, title: 'owner blocked too', body: 'four' })).s, 403);
  const sub = (await owner.post('/admin/forums', { category_id: cat, parent_id: f, name: 'Sub of hidden' })).j.id;
  assert.equal((await c.post('/threads', { forum_id: sub, title: 'blocked by parent', body: 'five' })).s, 403);
  await owner.patch(`/admin/forums/${f}`, { thread_perm: 'CREATE_THREAD' });
  assert.equal((await owner.put('/admin/settings/threads_disabled', { value: true })).s, 200);
  assert.equal((await c.post('/threads', { forum_id: f, title: 'blocked globally', body: 'six' })).s, 403);
  assert.equal((await c.get('/config')).j.threads_disabled, true);
  await owner.put('/admin/settings/threads_disabled', { value: false });
  assert.equal((await c.post('/threads', { forum_id: f, title: 'allowed again', body: 'seven' })).s, 201);
});
test('announcements: admin list shows scheduled/expired, edit, clear expiry, staff-only visibility', async () => {
  owner = new C(); assert.equal((await owner.post('/auth/login', { username: 'Aiden', password: 'Owner-Pass-12345' })).s, 200);
  const soon = new Date(Date.now() + 864e5).toISOString(), c = await user('AnnReader');
  const a = (await owner.post('/admin/announcements', { title: 'Scheduled one', body: 'later', publish_at: soon })).j;
  const b = (await owner.post('/admin/announcements', { title: 'Staff only', body: 'secret', visibility: 'staff' })).j;
  assert.ok(!(await c.get('/announcements')).j.some(x => x.id === a.id), 'scheduled not public yet');
  assert.ok((await owner.get('/admin/announcements')).j.some(x => x.id === a.id), 'but visible to the admin');
  assert.ok(!(await c.get('/announcements')).j.some(x => x.id === b.id), 'staff-only hidden from members');
  assert.equal((await owner.patch(`/admin/announcements/${a.id}`, { title: 'Edited', category: 'News', publish_at: new Date(Date.now() - 1000).toISOString(), expires_at: new Date(Date.now() + 36e5).toISOString() })).s, 200);
  assert.ok((await c.get('/announcements')).j.some(x => x.id === a.id && x.title === 'Edited' && x.category === 'News'));
  assert.equal((await owner.patch(`/admin/announcements/${a.id}`, { expires_at: null })).j.expires_at, null, 'expiry can be cleared');
  assert.equal((await c.get('/admin/announcements')).s, 403);
});
test('thread form fields: owner defines them per forum, threads store and edit values, validation', async () => {
  const f = await forumId('General Discussion'), c = await user('FieldPoster');
  const def = [{ key: 'game_id', label: 'Your ID', hint: 'In-game ID', required: true }, { key: 'day', label: 'Date of violation', type: 'date' }, { key: 'proofs', label: 'Proofs', type: 'url' }];
  assert.equal((await c.patch(`/admin/forums/${f}`, { fields: def })).s, 403);
  assert.equal((await owner.patch(`/admin/forums/${f}`, { fields: def })).s, 200);
  assert.equal((await c.post('/threads', { forum_id: f, title: 'no required field', body: 'x', fields: {} })).s, 400);
  assert.equal((await c.post('/threads', { forum_id: f, title: 'bad link', body: 'x', fields: { game_id: '1', proofs: 'javascript:alert(1)' } })).s, 400);
  const r = await c.post('/threads', { forum_id: f, title: 'with fields', body: 'x', fields: { game_id: '21535', day: '2024-04-05', proofs: 'https://streamable.com/0859hf', junk: 'dropped' } });
  assert.equal(r.s, 201, JSON.stringify(r.j));
  const t = (await c.get('/threads/' + r.j.id)).j.thread;
  assert.deepEqual(t.fields, { game_id: '21535', day: '2024-04-05', proofs: 'https://streamable.com/0859hf' });
  assert.equal((await c.patch('/threads/' + r.j.id, { fields: { game_id: '999' } })).s, 200);
  assert.equal((await c.get('/threads/' + r.j.id)).j.thread.fields.game_id, '999');
  assert.ok((await c.get('/forums')).j.categories.flatMap(k => k.forums).some(x => x.id === f && x.fields?.length === 3));
  await owner.patch(`/admin/forums/${f}`, { fields: [] });
});
test('report centre: context, filters, search, priority, bulk, detail, duplicates', async () => {
  const f = await forumId('General Discussion'), a = await user('RepAuthor'), b = await user('RepFiler1'), c = await user('RepFiler2');
  const th = (await a.post('/threads', { forum_id: f, title: 'Reported thread', body: 'some rude words here' })).j;
  const post = (await db.one('SELECT id FROM posts WHERE thread_id=$1', [th.id])).id;
  const r1 = (await b.post('/reports', { target_type: 'post', target_id: post, category: 'Harassment', details: 'insulting' })).j;
  const r2 = (await c.post('/reports', { target_type: 'post', target_id: post, category: 'Spam' })).j;
  assert.equal((await b.get('/staff/reports')).s, 403);
  const list = (await owner.get('/staff/reports?q=rude')).j;
  assert.ok(list.total >= 2 && list.items.every(x => x.thread_title === 'Reported thread' && x.target_user === 'RepAuthor' && x.dupes >= 1), JSON.stringify(list.items[0]));
  assert.equal((await owner.get('/staff/reports?q=insulting')).j.total, 1);
  assert.equal((await owner.get('/staff/reports?type=user')).j.items.filter(x => x.id === r1.id).length, 0);
  assert.equal((await owner.patch(`/staff/reports/${r1.id}`, { priority: 'urgent' })).s, 200);
  assert.equal((await owner.patch(`/staff/reports/${r1.id}`, { priority: 'nope' })).s, 400);
  assert.equal((await owner.get('/staff/reports?priority=urgent')).j.items[0].id, r1.id);
  assert.equal((await owner.get('/staff/reports?sort=priority')).j.items[0].id, r1.id);
  const sts = (await owner.get('/statuses?scope=report')).j, closed = sts.find(s => s.is_closed);
  const me = (await db.one("SELECT id FROM users WHERE username='Aiden'")).id;
  assert.equal((await owner.post('/staff/reports/bulk', { ids: [r1.id, r2.id], status_id: closed.id, assignee_id: me })).j.changed, 2);
  assert.equal((await owner.get('/staff/reports?mine=1&open=0')).j.total >= 2, true);
  assert.equal((await owner.post('/staff/reports/bulk', { ids: [], status_id: closed.id })).s, 400);
  const d = (await owner.get(`/staff/reports/${r1.id}`)).j;
  assert.equal(d.same.length, 1); assert.equal(d.target.username, 'RepAuthor'); assert.equal(d.report.assignee, 'Aiden');
  const sm = (await owner.get('/staff/reports/summary')).j; assert.ok(sm.by_status.length && typeof sm.open === 'number' && sm.resolved_7d >= 2);
  assert.equal((await owner.get(`/staff/reports/${r1.id}/log`)).j.history.length >= 2, true);
});
test('contact form: anyone can send, only staff can read, bad input is rejected', async () => {
  const anon = new C('9.9.9.9');
  assert.equal((await anon.post('/contact', { name: 'Zed', email: 'not-an-email', subject: 's', message: 'm' })).s, 400);
  assert.equal((await anon.post('/contact', { name: 'Zed', email: 'zed@ex.com', subject: 'Hello', message: 'I need help' })).s, 201);
  assert.ok([401, 403].includes((await alice.get('/staff/contact')).s));
  const l = await owner.get('/staff/contact'); assert.equal(l.s, 200); assert.ok(l.j.some(x => x.subject === 'Hello'));
  const id = l.j.find(x => x.subject === 'Hello').id;
  assert.equal((await owner.patch(`/staff/contact/${id}`, { is_read: true })).s, 200);
  assert.equal((await owner.del(`/staff/contact/${id}`)).s, 200);
});
