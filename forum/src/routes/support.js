import { Router } from 'express';
import { wrap, bad, str, int, oneOf, paging, HttpError, forbid, nf } from '../util.js';

export default function (ctx) {
  const r = Router(), { db } = ctx, can = ctx.can;
  const defStatus = async (scope, name) => (await db.one('SELECT id FROM statuses WHERE scope=$1 AND (name=$2 OR $2 IS NULL) ORDER BY sort LIMIT 1', [scope, name ?? null])).id;
  const mediaOk = async (id, uid) => { if (id == null) return null; id = int(id, 'media_id'); if (!(await db.one('SELECT 1 x FROM media WHERE id=$1 AND owner_id=$2', [id, uid]))) throw bad('Attachment not found'); return id; };
  r.get('/statuses', wrap(async (req, res) => res.json(await db.q('SELECT * FROM statuses WHERE ($1::text IS NULL OR scope=$1) ORDER BY scope,sort', [req.query.scope || null]))));

  // generic staff case handling (status, assignee, history, internal notes) for reports/appeals/applications/tickets
  function staffCases(base, table, scope, perm, ownerCol, label) {
    const P = ctx.need(perm);
    r.get(`/staff/${base}`, P, wrap(async (req, res) => {
      const { limit, offset } = paging(req, 30, 100);
      res.json(await db.q(`SELECT c.*, s.name AS status, s.color AS status_color, s.is_closed, u.username AS ${ownerCol === 'reporter_id' ? 'reporter' : 'user'}, a.username AS assignee FROM ${table} c JOIN statuses s ON s.id=c.status_id JOIN users u ON u.id=c.${ownerCol} LEFT JOIN users a ON a.id=c.assignee_id
        WHERE ($1::int IS NULL OR c.status_id=$1) AND ($2::int IS NULL OR c.assignee_id=$2) AND ($3::boolean IS NOT TRUE OR NOT s.is_closed) ORDER BY c.id DESC LIMIT ${limit} OFFSET ${offset}`,
        [req.query.status_id ? int(req.query.status_id) : null, req.query.assignee_id ? int(req.query.assignee_id) : null, req.query.open === '1' ? true : null]));
    }));
    r.patch(`/staff/${base}/:id`, P, wrap(async (req, res) => {
      const id = int(req.params.id), c = await db.one(`SELECT * FROM ${table} WHERE id=$1`, [id]); if (!c) throw nf();
      const b = req.body, sets = [], args = [id], add = (k, v) => { args.push(v); sets.push(`${k}=$${args.length}`); };
      let newStatus = null;
      if (b.status_id != null) { newStatus = await db.one('SELECT * FROM statuses WHERE id=$1 AND scope=$2', [int(b.status_id, 'status_id'), scope]); if (!newStatus) throw bad('Unknown status'); add('status_id', newStatus.id); }
      if ('assignee_id' in b) { if (b.assignee_id !== null) { const a = await db.one('SELECT id FROM users WHERE id=$1', [int(b.assignee_id)]); if (!a) throw bad('Assignee not found'); } add('assignee_id', b.assignee_id); }
      if ('priority' in b && table === 'reports') add('priority', oneOf(b.priority, ['low', 'normal', 'high', 'urgent'], 'priority'));
      if ('resolution' in b && table === 'reports') add('resolution', str(b.resolution, 'Resolution', { max: 2000, optional: true }));
      if (!sets.length) return res.json({ ok: true });
      await db.q(`UPDATE ${table} SET ${sets.join(',')}, updated_at=now() WHERE id=$1`, args);
      if (newStatus) {
        const old = await db.one('SELECT name FROM statuses WHERE id=$1', [c.status_id]);
        await db.q("INSERT INTO history (entity,entity_id,action,from_value,to_value,actor_id) VALUES ($1,$2,'status',$3,$4,$5)", [scope, id, old.name, newStatus.name, req.user.id]);
        await ctx.notify(c[ownerCol], 'case_update', { kind: label, id, status: newStatus.name });
      }
      if ('assignee_id' in b) await db.q("INSERT INTO history (entity,entity_id,action,to_value,actor_id) VALUES ($1,$2,'assign',$3,$4)", [scope, id, String(b.assignee_id), req.user.id]);
      await ctx.audit(req, `${scope}_update`, scope, id, null, b); res.json({ ok: true });
    }));
    r.get(`/staff/${base}/:id/log`, P, wrap(async (req, res) => { const id = int(req.params.id); res.json({ history: await db.q('SELECT h.*, u.username AS actor FROM history h LEFT JOIN users u ON u.id=h.actor_id WHERE entity=$1 AND entity_id=$2 ORDER BY h.id', [scope, id]), notes: await db.q('SELECT n.*, u.username AS author FROM notes n LEFT JOIN users u ON u.id=n.author_id WHERE entity=$1 AND entity_id=$2 ORDER BY n.id', [scope, id]) }); }));
    r.post(`/staff/${base}/:id/notes`, P, wrap(async (req, res) => { await db.q('INSERT INTO notes (entity,entity_id,author_id,body) VALUES ($1,$2,$3,$4)', [scope, int(req.params.id), req.user.id, str(req.body.body, 'Note', { max: 3000 })]); res.status(201).json({ ok: true }); }));
  }

  // ---- advanced report centre (registered before the generic handlers so the list / detail carry full context) ----
  const PRI = ['low', 'normal', 'high', 'urgent'], RP = ctx.need('HANDLE_REPORTS');
  const RFROM = `FROM reports c JOIN statuses s ON s.id=c.status_id JOIN users ru ON ru.id=c.reporter_id LEFT JOIN users a ON a.id=c.assignee_id
    LEFT JOIN posts p ON c.target_type='post' AND p.id=c.target_id
    LEFT JOIN threads t ON t.id = CASE WHEN c.target_type='thread' THEN c.target_id ELSE p.thread_id END
    LEFT JOIN users tu ON tu.id = CASE c.target_type WHEN 'post' THEN p.author_id WHEN 'thread' THEN t.author_id WHEN 'user' THEN c.target_id WHEN 'profile' THEN c.target_id END`;
  const RSEL = `SELECT c.id, c.reporter_id, c.target_type, c.target_id, c.category, c.details, c.status_id, c.assignee_id, c.resolution, c.priority, c.created_at, c.updated_at,
    s.name AS status, s.color AS status_color, s.is_closed, ru.username AS reporter, a.username AS assignee,
    t.id AS thread_id, t.title AS thread_title, left(p.body, 300) AS excerpt, (p.deleted_at IS NOT NULL OR p.hidden) AS post_removed, tu.id AS target_user_id, tu.username AS target_user,
    (SELECT count(*)::int FROM reports d JOIN statuses ds ON ds.id=d.status_id WHERE d.id<>c.id AND d.target_type=c.target_type AND d.target_id IS NOT DISTINCT FROM c.target_id AND NOT ds.is_closed) AS dupes `;
  r.get('/staff/reports', RP, wrap(async (req, res) => {
    const { limit, offset } = paging(req, 25, 100), q = req.query, args = [], w = [];
    const add = (cond, v) => { args.push(v); w.push(cond.replace('?', '$' + args.length)); };
    if (q.status_id) add('c.status_id=?', int(q.status_id, 'status_id'));
    if (q.open === '1') w.push('NOT s.is_closed'); if (q.open === '0') w.push('s.is_closed');
    if (q.type) add('c.target_type=?', oneOf(q.type, ['post', 'thread', 'user', 'message', 'profile', 'other'], 'type'));
    if (q.priority) add('c.priority=?', oneOf(q.priority, PRI, 'priority'));
    if (q.category) add('c.category=?', String(q.category).slice(0, 60));
    if (q.mine === '1') add('c.assignee_id=?', req.user.id);
    if (q.unassigned === '1') w.push('c.assignee_id IS NULL');
    if (q.assignee_id) add('c.assignee_id=?', int(q.assignee_id, 'assignee_id'));
    if (q.q) { const like = '%' + String(q.q).slice(0, 80).replace(/[%_]/g, m => '\\' + m) + '%'; args.push(like); const n = args.length; args.push(String(q.q).slice(0, 80)); w.push(`(c.category ILIKE $${n} OR c.details ILIKE $${n} OR ru.username ILIKE $${n} OR tu.username ILIKE $${n} OR t.title ILIKE $${n} OR p.body ILIKE $${n} OR c.id::text=$${n + 1})`); }
    const order = { old: 'c.created_at ASC', updated: 'c.updated_at DESC', priority: "array_position(ARRAY['urgent','high','normal','low'], c.priority), c.created_at ASC" }[q.sort] || 'c.created_at DESC';
    const where = w.length ? 'WHERE ' + w.join(' AND ') : '';
    const total = (await db.one(`SELECT count(*)::int n ${RFROM} ${where}`, args)).n;
    res.json({ total, items: await db.q(`${RSEL} ${RFROM} ${where} ORDER BY ${order}, c.id DESC LIMIT ${limit} OFFSET ${offset}`, args) });
  }));
  r.get('/staff/reports/summary', RP, wrap(async (req, res) => {
    const one = async (sql, a = []) => (await db.one(sql, a)).n;
    const by = await db.q('SELECT s.id, s.name, s.color, s.is_closed, count(c.id)::int AS n FROM statuses s LEFT JOIN reports c ON c.status_id=s.id WHERE s.scope=$1 GROUP BY s.id ORDER BY s.sort, s.id', ['report']);
    res.json({
      open: await one('SELECT count(*)::int n FROM reports c JOIN statuses s ON s.id=c.status_id WHERE NOT s.is_closed'),
      unassigned: await one('SELECT count(*)::int n FROM reports c JOIN statuses s ON s.id=c.status_id WHERE NOT s.is_closed AND c.assignee_id IS NULL'),
      mine: await one('SELECT count(*)::int n FROM reports c JOIN statuses s ON s.id=c.status_id WHERE NOT s.is_closed AND c.assignee_id=$1', [req.user.id]),
      urgent: await one("SELECT count(*)::int n FROM reports c JOIN statuses s ON s.id=c.status_id WHERE NOT s.is_closed AND c.priority IN ('urgent','high')"),
      resolved_7d: await one("SELECT count(*)::int n FROM reports c JOIN statuses s ON s.id=c.status_id WHERE s.is_closed AND c.updated_at > now() - interval '7 days'"),
      oldest_open_hours: (await db.one('SELECT COALESCE(EXTRACT(EPOCH FROM now()-min(c.created_at))/3600,0)::int AS n FROM reports c JOIN statuses s ON s.id=c.status_id WHERE NOT s.is_closed')).n,
      by_status: by,
      categories: await db.q('SELECT category, count(*)::int n FROM reports GROUP BY category ORDER BY n DESC LIMIT 12'),
    });
  }));
  r.get('/staff/reports/:id', RP, wrap(async (req, res) => {
    const id = int(req.params.id), rep = await db.one(`${RSEL} ${RFROM} WHERE c.id=$1`, [id]); if (!rep) throw nf();
    const reporter = await db.one("SELECT (SELECT count(*)::int FROM reports WHERE reporter_id=$1) AS filed, (SELECT count(*)::int FROM reports x JOIN statuses xs ON xs.id=x.status_id WHERE x.reporter_id=$1 AND xs.is_closed AND x.resolution ILIKE 'no violation%') AS dismissed", [rep.reporter_id]);
    const target = rep.target_user_id ? await db.one("SELECT u.id, u.username, u.created_at, (SELECT count(*)::int FROM sanctions WHERE user_id=u.id AND type='warn') AS warns, (SELECT count(*)::int FROM sanctions WHERE user_id=u.id AND type='timeout') AS timeouts, (SELECT count(*)::int FROM sanctions WHERE user_id=u.id AND type='ban') AS bans, (SELECT count(*)::int FROM reports WHERE target_type IN ('post','thread','user','profile') AND id<>$2 AND (CASE target_type WHEN 'user' THEN target_id WHEN 'profile' THEN target_id ELSE NULL END)=u.id) AS other_reports FROM users u WHERE u.id=$1", [rep.target_user_id, id]) : null;
    const same = await db.q(`SELECT c.id, c.category, c.created_at, s.name AS status, ru.username AS reporter FROM reports c JOIN statuses s ON s.id=c.status_id JOIN users ru ON ru.id=c.reporter_id WHERE c.id<>$1 AND c.target_type=$2 AND c.target_id IS NOT DISTINCT FROM $3 ORDER BY c.id DESC LIMIT 10`, [id, rep.target_type, rep.target_id]);
    res.json({ report: rep, reporter, target, same });
  }));
  r.post('/staff/reports/bulk', RP, wrap(async (req, res) => {
    const ids = (Array.isArray(req.body.ids) ? req.body.ids : []).map(x => int(x, 'id')).slice(0, 100); if (!ids.length) throw bad('Select at least one report');
    const b = req.body; let st = null; if (b.status_id != null) { st = await db.one('SELECT * FROM statuses WHERE id=$1 AND scope=$2', [int(b.status_id, 'status_id'), 'report']); if (!st) throw bad('Unknown status'); }
    if ('assignee_id' in b && b.assignee_id !== null) { if (!(await db.one('SELECT id FROM users WHERE id=$1', [int(b.assignee_id)]))) throw bad('Assignee not found'); }
    const pri = b.priority != null ? oneOf(b.priority, PRI, 'priority') : null; if (!st && !pri && !('assignee_id' in b)) throw bad('Nothing to change');
    let n = 0;
    for (const id of ids) {
      const c = await db.one('SELECT c.*, s.name AS sname FROM reports c JOIN statuses s ON s.id=c.status_id WHERE c.id=$1', [id]); if (!c) continue;
      await db.q('UPDATE reports SET status_id=COALESCE($2,status_id), priority=COALESCE($3,priority), assignee_id=CASE WHEN $5 THEN $4 ELSE assignee_id END, updated_at=now() WHERE id=$1', [id, st?.id ?? null, pri, 'assignee_id' in b ? b.assignee_id : null, 'assignee_id' in b]);
      if (st && st.id !== c.status_id) { await db.q("INSERT INTO history (entity,entity_id,action,from_value,to_value,actor_id) VALUES ('report',$1,'status',$2,$3,$4)", [id, c.sname, st.name, req.user.id]); await ctx.notify(c.reporter_id, 'case_update', { kind: 'report', id, status: st.name }); }
      if ('assignee_id' in b) await db.q("INSERT INTO history (entity,entity_id,action,to_value,actor_id) VALUES ('report',$1,'assign',$2,$3)", [id, String(b.assignee_id), req.user.id]);
      if (pri && pri !== c.priority) await db.q("INSERT INTO history (entity,entity_id,action,from_value,to_value,actor_id) VALUES ('report',$1,'priority',$2,$3,$4)", [id, c.priority, pri, req.user.id]);
      n++;
    }
    await ctx.audit(req, 'report_bulk', 'report', null, null, { ids, ...b }); res.json({ ok: true, changed: n });
  }));
  staffCases('reports', 'reports', 'report', 'HANDLE_REPORTS', 'reporter_id', 'report');
  // ---- reports ----
  r.post('/reports', ctx.authed, ctx.limit(20, 3600_000), wrap(async (req, res) => {
    if (!can(req.user, 'REPORT')) throw forbid();
    const type = oneOf(req.body.target_type, ['post', 'thread', 'user', 'message', 'profile', 'other'], 'target_type');
    const rep = await db.one('INSERT INTO reports (reporter_id,target_type,target_id,category,details,status_id) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id',
      [req.user.id, type, req.body.target_id != null ? int(req.body.target_id, 'target_id') : null, str(req.body.category, 'Category', { max: 60 }), str(req.body.details, 'Details', { max: 2000, optional: true }), await defStatus('report')]);
    res.status(201).json(rep);
  }));

  // ---- contact form (public) + staff inbox ----
  r.post('/contact', ctx.limit(5, 3600_000), wrap(async (req, res) => {
    const name = str(req.body.name, 'Name', { max: 80 }), email = str(req.body.email, 'Email', { max: 200 });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw bad('Enter a valid email address');
    const subject = str(req.body.subject, 'Subject', { max: 150 }), message = str(req.body.message, 'Message', { max: 5000 });
    const row = await db.one('INSERT INTO contact_messages (user_id,name,email,subject,message,ip) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id', [req.user ? req.user.id : null, name, email, subject, message, req.ip || null]);
    res.status(201).json({ id: row.id });
  }));
  const CP = ctx.need('HANDLE_REPORTS');
  r.get('/staff/contact', CP, wrap(async (req, res) => res.json(await db.q('SELECT id,user_id,name,email,subject,message,is_read,created_at FROM contact_messages ORDER BY id DESC LIMIT 200'))));
  r.patch('/staff/contact/:id', CP, wrap(async (req, res) => { await db.q('UPDATE contact_messages SET is_read=$2 WHERE id=$1', [int(req.params.id), req.body.is_read !== false]); res.json({ ok: true }); }));
  r.delete('/staff/contact/:id', CP, wrap(async (req, res) => { await db.q('DELETE FROM contact_messages WHERE id=$1', [int(req.params.id)]); await ctx.audit(req, 'contact_delete', 'contact', int(req.params.id), null, null); res.json({ ok: true }); }));

  r.get('/me/sanctions', ctx.authed, wrap(async (req, res) => res.json(await db.q("SELECT id,type,reason,created_at,expires_at,revoked_at FROM sanctions WHERE user_id=$1 AND type<>'unban' ORDER BY id DESC", [req.user.id]))));
  return r;
}
