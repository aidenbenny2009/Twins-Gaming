import { Router } from 'express';
import crypto from 'node:crypto';
import { wrap, bad, str, int, bool, oneOf, safeUrl, forbid, nf, HttpError } from '../util.js';
import { sha256 } from '../security.js';

export default function (ctx) {
  const r = Router(), { db } = ctx, can = ctx.can;
  const M = ctx.need('MANAGE_CONTENT');
  const visOk = (u, v) => v === 'public' || (v === 'members' && u) || (v === 'staff' && u?.isStaff);

  r.get('/config', wrap(async (req, res) => {
    const [links, nav, texts, theme, seo, m, reg, name, tag] = await Promise.all([db.q('SELECT id,name,url,icon,location,new_tab,sort FROM links WHERE visible ORDER BY sort,id'), db.q('SELECT id,menu,parent_id,label,url,icon,sort FROM nav_items WHERE visible ORDER BY sort,id'), db.q('SELECT key,value FROM content_texts'), ctx.setting('theme'), ctx.setting('seo'), ctx.setting('maintenance'), ctx.setting('registration_open'), ctx.setting('site_name'), ctx.setting('tagline')]);
    const pages = await db.q("SELECT slug,title,nav_placement FROM pages WHERE published AND visibility='public' ORDER BY title");
    res.json({ threads_disabled: !!(await ctx.setting('threads_disabled')), site_name: name, tagline: tag, registration_open: reg, maintenance: !!m?.on, theme: { default: theme.default, accent: theme.accent, custom_css: theme.custom_css || '' }, seo, links, nav, texts: Object.fromEntries(texts.map(t => [t.key, t.value])), pages, turnstile_site: ctx.cfg.turnstileSite || null, rss_url: await ctx.setting('rss_url'), footer_a: await ctx.setting('footer_a'), footer_b: await ctx.setting('footer_b'), footer_since: await ctx.setting('footer_since'), admin_signature: await ctx.setting('admin_signature'), banner_url: await ctx.setting('banner_url'), google_client_id: ctx.cfg.googleClientId || null });
  }));
  r.get('/robots-meta', wrap(async (req, res) => res.json(await ctx.setting('seo'))));

  // ---- rules with revision history ----
  async function canSeeRevisions(u) { if (!u) return false; if (u.is_owner) return true; if (await ctx.setting('rules_revisions_public')) return true; return !!(await db.one('SELECT 1 x FROM revision_viewers WHERE user_id=$1', [u.id])); }
  r.get('/rules', wrap(async (req, res) => {
    const secs = await db.q('SELECT * FROM rule_sections ORDER BY sort,id'), staff = req.user && can(req.user, 'MANAGE_RULES');
    const rules = await db.q(`SELECT id,section_id,title,body,status,sort,updated_at FROM rules WHERE ($1::boolean OR status='published') AND status<>'archived' OR ($1::boolean) ORDER BY sort,id`, [!!staff]);
    res.json({ sections: secs.map(s => ({ ...s, rules: rules.filter(x => x.section_id === s.id) })), can_see_revisions: await canSeeRevisions(req.user) });
  }));
  r.get('/rules/:id/revisions', ctx.authed, wrap(async (req, res) => {
    if (!(await canSeeRevisions(req.user))) throw forbid('Revision history is not available to you');
    res.json(await db.q('SELECT v.id,v.title,v.body,v.created_at,u.username AS editor FROM rule_revisions v LEFT JOIN users u ON u.id=v.editor_id WHERE v.rule_id=$1 ORDER BY v.id DESC', [int(req.params.id)]));
  }));
  r.put('/admin/revision-viewers/:userId', ctx.ownerOnly, wrap(async (req, res) => { await db.q('INSERT INTO revision_viewers (user_id,granted_by) VALUES ($1,$2) ON CONFLICT DO NOTHING', [int(req.params.userId), req.user.id]); await ctx.audit(req, 'revision_viewer_grant', 'user', req.params.userId); res.json({ ok: true }); }));
  r.delete('/admin/revision-viewers/:userId', ctx.ownerOnly, wrap(async (req, res) => { await db.q('DELETE FROM revision_viewers WHERE user_id=$1', [int(req.params.userId)]); await ctx.audit(req, 'revision_viewer_revoke', 'user', req.params.userId); res.json({ ok: true }); }));
  const R = ctx.need('MANAGE_RULES');
  r.post('/admin/rule-sections', R, wrap(async (req, res) => res.status(201).json(await db.one('INSERT INTO rule_sections (name,sort) VALUES ($1,$2) RETURNING *', [str(req.body.name, 'Name', { max: 100 }), +req.body.sort || 0]))));
  r.patch('/admin/rule-sections/:id', R, wrap(async (req, res) => { const s = await db.one('UPDATE rule_sections SET name=COALESCE($2,name), sort=COALESCE($3,sort) WHERE id=$1 RETURNING *', [int(req.params.id), req.body.name ? str(req.body.name, 'Name', { max: 100 }) : null, req.body.sort ?? null]); if (!s) throw nf(); await ctx.audit(req, 'rule_section_update', 'rule_section', s.id); res.json(s); }));
  r.delete('/admin/rule-sections/:id', R, ctx.reauth, wrap(async (req, res) => { await db.q('DELETE FROM rule_sections WHERE id=$1', [int(req.params.id)]); await ctx.audit(req, 'rule_section_delete', 'rule_section', req.params.id); res.json({ ok: true }); }));
  r.post('/admin/rules', R, wrap(async (req, res) => {
    const b = req.body, rule = await db.one('INSERT INTO rules (section_id,title,body,status,sort,updated_by) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *', [int(b.section_id, 'section_id'), str(b.title, 'Title', { max: 200 }), str(b.body, 'Body', { max: 20000 }), oneOf(b.status || 'draft', ['draft', 'published', 'archived'], 'status'), +b.sort || 0, req.user.id]);
    await db.q('INSERT INTO rule_revisions (rule_id,title,body,editor_id) VALUES ($1,$2,$3,$4)', [rule.id, rule.title, rule.body, req.user.id]); await ctx.audit(req, 'rule_create', 'rule', rule.id); res.status(201).json(rule);
  }));
  r.patch('/admin/rules/:id', R, wrap(async (req, res) => {
    const id = int(req.params.id), old = await db.one('SELECT * FROM rules WHERE id=$1', [id]); if (!old) throw nf(); const b = req.body;
    const n = { title: b.title != null ? str(b.title, 'Title', { max: 200 }) : old.title, body: b.body != null ? str(b.body, 'Body', { max: 20000 }) : old.body, status: b.status ? oneOf(b.status, ['draft', 'published', 'archived'], 'status') : old.status, sort: b.sort ?? old.sort, section_id: b.section_id ?? old.section_id };
    await db.tx(async t => { await t.q('INSERT INTO rule_revisions (rule_id,title,body,editor_id) VALUES ($1,$2,$3,$4)', [id, n.title, n.body, req.user.id]); await t.q('UPDATE rules SET title=$2,body=$3,status=$4,sort=$5,section_id=$6,updated_by=$7,updated_at=now() WHERE id=$1', [id, n.title, n.body, n.status, n.sort, n.section_id, req.user.id]); });
    await ctx.audit(req, 'rule_update', 'rule', id, { title: old.title, status: old.status }, { title: n.title, status: n.status }); res.json({ ok: true });
  }));
  r.delete('/admin/rules/:id', R, ctx.reauth, wrap(async (req, res) => { await db.q('DELETE FROM rules WHERE id=$1', [int(req.params.id)]); await ctx.audit(req, 'rule_delete', 'rule', req.params.id); res.json({ ok: true }); }));

  // ---- announcements ----
  r.get('/announcements', wrap(async (req, res) => {
    const rows = await db.q('SELECT a.*, u.username AS author FROM announcements a LEFT JOIN users u ON u.id=a.author_id WHERE a.publish_at<=now() AND (a.expires_at IS NULL OR a.expires_at>now()) ORDER BY a.pinned DESC, a.publish_at DESC LIMIT 100');
    res.json(rows.filter(a => visOk(req.user, a.visibility)));
  }));
  const A = ctx.need('MANAGE_ANNOUNCEMENTS');
  r.post('/admin/announcements', A, wrap(async (req, res) => {
    const b = req.body, a = await db.one('INSERT INTO announcements (title,body,image_url,banner_url,category,author_id,publish_at,expires_at,pinned,featured,visibility) VALUES ($1,$2,$3,$4,$5,$6,COALESCE($7::timestamptz,now()),$8::timestamptz,$9,$10,$11) RETURNING *',
      [str(b.title, 'Title', { max: 200 }), str(b.body, 'Body', { max: 20000 }), b.image_url || null, b.banner_url || null, b.category || null, req.user.id, b.publish_at || null, b.expires_at || null, !!b.pinned, !!b.featured, oneOf(b.visibility || 'public', ['public', 'members', 'staff'], 'visibility')]);
    await ctx.audit(req, 'announcement_create', 'announcement', a.id);
    if (b.notify) { const us = await db.q("SELECT id,email FROM users WHERE status='active' AND email_verified AND COALESCE(prefs->>'email_notifications','true')<>'false'"); for (const u of us) { await ctx.notify(u.id, 'announcement', { id: a.id, title: a.title }); if (b.email) await ctx.mail.send(u.email, 'announcement', { title: a.title }); } await db.q('UPDATE announcements SET notified=true WHERE id=$1', [a.id]); }
    res.status(201).json(a);
  }));
  r.get('/admin/announcements', A, wrap(async (req, res) => res.json(await db.q('SELECT a.*, u.username AS author FROM announcements a LEFT JOIN users u ON u.id=a.author_id ORDER BY a.pinned DESC, a.publish_at DESC LIMIT 300'))));
  r.patch('/admin/announcements/:id', A, wrap(async (req, res) => {
    const b = req.body, id = int(req.params.id), sets = [], args = [id], add = (k, v, cast = '') => { args.push(v); sets.push(`${k}=$${args.length}${cast}`); };
    if (b.title != null) add('title', str(b.title, 'Title', { max: 200 })); if (b.body != null) add('body', str(b.body, 'Body', { max: 20000 }));
    if ('category' in b) add('category', b.category ? str(b.category, 'Category', { max: 60 }) : null);
    if (b.pinned != null) add('pinned', !!b.pinned); if (b.featured != null) add('featured', !!b.featured);
    if (b.visibility != null) add('visibility', oneOf(b.visibility, ['public', 'members', 'staff'], 'visibility'));
    if ('expires_at' in b) add('expires_at', b.expires_at || null, '::timestamptz'); if (b.publish_at) add('publish_at', b.publish_at, '::timestamptz');
    if (!sets.length) return res.json({ ok: true });
    const a = await db.one(`UPDATE announcements SET ${sets.join(',')} WHERE id=$1 RETURNING *`, args); if (!a) throw nf();
    await ctx.audit(req, 'announcement_update', 'announcement', a.id, null, b); res.json(a);
  }));
  r.delete('/admin/announcements/:id', A, wrap(async (req, res) => { await db.q('DELETE FROM announcements WHERE id=$1', [int(req.params.id)]); await ctx.audit(req, 'announcement_delete', 'announcement', req.params.id); res.json({ ok: true }); }));

  // ---- CMS: pages, links, nav, texts, email templates, media ----
  r.get('/pages/:slug', wrap(async (req, res) => { const p = await db.one('SELECT * FROM pages WHERE slug=$1', [req.params.slug]); if (!p || (!p.published && !(req.user && can(req.user, 'MANAGE_CONTENT'))) || !visOk(req.user, p.visibility)) throw nf('Page not found'); res.json(p); }));
  r.get('/admin/pages', M, wrap(async (req, res) => res.json(await db.q('SELECT * FROM pages ORDER BY title'))));
  r.put('/admin/pages/:slug', M, wrap(async (req, res) => {
    const b = req.body, slug = req.params.slug; if (!/^[a-z0-9-]{1,60}$/.test(slug)) throw bad('Slug may contain a-z, 0-9 and -');
    const p = await db.one(`INSERT INTO pages (slug,title,body,image_url,seo_title,seo_description,visibility,nav_placement,published) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
      ON CONFLICT (slug) DO UPDATE SET title=EXCLUDED.title, body=EXCLUDED.body, image_url=EXCLUDED.image_url, seo_title=EXCLUDED.seo_title, seo_description=EXCLUDED.seo_description, visibility=EXCLUDED.visibility, nav_placement=EXCLUDED.nav_placement, published=EXCLUDED.published, updated_at=now() RETURNING *`,
      [slug, str(b.title, 'Title', { max: 200 }), String(b.body || '').slice(0, 100000), b.image_url || null, b.seo_title || null, b.seo_description || null, oneOf(b.visibility || 'public', ['public', 'members', 'staff'], 'visibility'), b.nav_placement || null, !!b.published]);
    await ctx.audit(req, 'page_save', 'page', slug); res.json(p);
  }));
  r.delete('/admin/pages/:slug', M, ctx.reauth, wrap(async (req, res) => { await db.q('DELETE FROM pages WHERE slug=$1', [req.params.slug]); await ctx.audit(req, 'page_delete', 'page', req.params.slug); res.json({ ok: true }); }));
  const LOC = ['header', 'homepage', 'forum', 'sidebar', 'footer', 'profile', 'announcements', 'custom'];
  r.get('/admin/links', M, wrap(async (req, res) => res.json(await db.q('SELECT * FROM links ORDER BY location,sort,id'))));
  r.post('/admin/links', M, wrap(async (req, res) => { const b = req.body; const l = await db.one('INSERT INTO links (name,url,icon,location,new_tab,visible,sort) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *', [str(b.name, 'Name', { max: 80 }), safeUrl(b.url), b.icon || null, oneOf(b.location, LOC, 'location'), b.new_tab !== false, b.visible !== false, +b.sort || 0]); await ctx.audit(req, 'link_create', 'link', l.id, null, l); res.status(201).json(l); }));
  r.patch('/admin/links/:id', M, wrap(async (req, res) => { const b = req.body; if (b.url) safeUrl(b.url); if (b.location) oneOf(b.location, LOC, 'location'); const l = await db.one('UPDATE links SET name=COALESCE($2,name), url=COALESCE($3,url), icon=COALESCE($4,icon), location=COALESCE($5,location), new_tab=COALESCE($6,new_tab), visible=COALESCE($7,visible), sort=COALESCE($8,sort) WHERE id=$1 RETURNING *', [int(req.params.id), b.name ?? null, b.url ?? null, b.icon ?? null, b.location ?? null, b.new_tab ?? null, b.visible ?? null, b.sort ?? null]); if (!l) throw nf(); await ctx.audit(req, 'link_update', 'link', l.id, null, l); res.json(l); }));
  r.delete('/admin/links/:id', M, wrap(async (req, res) => { await db.q('DELETE FROM links WHERE id=$1', [int(req.params.id)]); await ctx.audit(req, 'link_delete', 'link', req.params.id); res.json({ ok: true }); }));
  r.get('/admin/nav', M, wrap(async (req, res) => res.json(await db.q('SELECT * FROM nav_items ORDER BY menu,sort,id'))));
  r.post('/admin/nav', M, wrap(async (req, res) => { const b = req.body; const n = await db.one('INSERT INTO nav_items (menu,parent_id,label,url,icon,visible,sort) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *', [oneOf(b.menu, ['header', 'footer', 'mobile'], 'menu'), b.parent_id ? int(b.parent_id) : null, str(b.label, 'Label', { max: 60 }), safeUrl(b.url), b.icon || null, b.visible !== false, +b.sort || 0]); await ctx.audit(req, 'nav_create', 'nav', n.id); res.status(201).json(n); }));
  r.patch('/admin/nav/:id', M, wrap(async (req, res) => { const b = req.body; if (b.url) safeUrl(b.url); const n = await db.one('UPDATE nav_items SET label=COALESCE($2,label), url=COALESCE($3,url), icon=COALESCE($4,icon), visible=COALESCE($5,visible), sort=COALESCE($6,sort), parent_id=COALESCE($7,parent_id) WHERE id=$1 RETURNING *', [int(req.params.id), b.label ?? null, b.url ?? null, b.icon ?? null, b.visible ?? null, b.sort ?? null, b.parent_id ?? null]); if (!n) throw nf(); await ctx.audit(req, 'nav_update', 'nav', n.id); res.json(n); }));
  r.delete('/admin/nav/:id', M, wrap(async (req, res) => { await db.q('DELETE FROM nav_items WHERE id=$1', [int(req.params.id)]); await ctx.audit(req, 'nav_delete', 'nav', req.params.id); res.json({ ok: true }); }));
  r.get('/admin/texts', M, wrap(async (req, res) => res.json(await db.q('SELECT * FROM content_texts ORDER BY grp,key'))));
  r.put('/admin/texts/:key', M, wrap(async (req, res) => { await db.q('INSERT INTO content_texts (key,label,grp,value) VALUES ($1,$1,$2,$3) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value', [req.params.key.slice(0, 80), req.body.grp || 'Custom', str(req.body.value, 'Value', { max: 5000, min: 0, optional: true }) ?? '']); await ctx.audit(req, 'text_update', 'text', req.params.key); res.json({ ok: true }); }));
  r.get('/admin/email-templates', M, wrap(async (req, res) => res.json(await db.q('SELECT * FROM email_templates ORDER BY key'))));
  r.put('/admin/email-templates/:key', M, wrap(async (req, res) => { const b = req.body; const t = await db.one('UPDATE email_templates SET subject=COALESCE($2,subject), body_html=COALESCE($3,body_html), body_text=COALESCE($4,body_text), enabled=COALESCE($5,enabled) WHERE key=$1 RETURNING *', [req.params.key, b.subject ?? null, b.body_html ?? null, b.body_text ?? null, b.enabled ?? null]); if (!t) throw nf(); await ctx.audit(req, 'email_template_update', 'email_template', t.key); res.json(t); }));
  r.get('/admin/outbox', ctx.need('MANAGE_CONTENT'), wrap(async (req, res) => res.json(await db.q('SELECT id,to_email,template,subject,status,error,created_at FROM outbox ORDER BY id DESC LIMIT 200'))));
  r.get('/admin/media', ctx.need('MANAGE_MEDIA'), wrap(async (req, res) => res.json(await db.q('SELECT m.*, u.username AS owner FROM media m LEFT JOIN users u ON u.id=m.owner_id ORDER BY m.id DESC LIMIT 500'))));
  r.delete('/admin/media/:id', ctx.need('MANAGE_MEDIA'), wrap(async (req, res) => {
    const m = await db.one('DELETE FROM media WHERE id=$1 RETURNING filename', [int(req.params.id)]); if (!m) throw nf();
    const fs = await import('node:fs/promises'), path = await import('node:path'); await fs.unlink(path.join(ctx.cfg.uploadDir, m.filename)).catch(() => {}); await ctx.audit(req, 'media_delete', 'media', req.params.id); res.json({ ok: true });
  }));

  // ---- privacy-conscious analytics beacon ----
  r.post('/track', ctx.limit(120, 60_000), wrap(async (req, res) => {
    if (!(await ctx.setting('analytics_enabled')) || ((await ctx.setting('honor_dnt')) && req.get('dnt') === '1')) return res.status(204).end();
    const p = String(req.body.path || '/').split('?')[0].slice(0, 200), ua = req.get('user-agent') || '';
    const salt = new Date().toISOString().slice(0, 10) + ctx.cfg.secret; // daily-rotating hash: no cross-day tracking, no raw IPs stored
    const h = sha256(req.ip + ua + salt).slice(0, 32), device = /mobile|android|iphone/i.test(ua) ? 'mobile' : /tablet|ipad/i.test(ua) ? 'tablet' : 'desktop', browser = /edg\//i.test(ua) ? 'Edge' : /chrome/i.test(ua) ? 'Chrome' : /firefox/i.test(ua) ? 'Firefox' : /safari/i.test(ua) ? 'Safari' : 'Other';
    let ref = null; try { ref = req.body.referrer ? new URL(req.body.referrer).hostname.slice(0, 100) : null; } catch {}
    await db.q('INSERT INTO page_views (day,path,views) VALUES (current_date,$1,1) ON CONFLICT (day,path) DO UPDATE SET views=page_views.views+1', [p]);
    await db.q('INSERT INTO visitors (day,hash,device,browser,referrer) VALUES (current_date,$1,$2,$3,$4) ON CONFLICT DO NOTHING', [h, device, browser, ref]); res.status(204).end();
  }));
  // ---- live presence (guests + hidden visitors): in-memory, 15-minute window, no raw IPs kept ----
  const PRES = new Map();
  r.get('/presence', ctx.limit(60, 60_000), wrap(async (req, res) => {
    const now = Date.now(), win = 15 * 60_000, salt = ctx.cfg.secret;
    if (!req.user) PRES.set(sha256(req.ip + (req.get('user-agent') || '') + salt).slice(0, 24), now);
    for (const [k, t] of PRES) if (now - t > win) PRES.delete(k);
    res.json({ guests: PRES.size });
  }));
  return r;
}
