import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import fs from 'node:fs';
import path from 'node:path';
import { HttpError, wrap, forbid } from './util.js';
import { sha256, token, safeEq } from './security.js';
import { makeMailer } from './mail.js';
import { DEFAULT_SETTINGS } from './seed.js';
import authRoutes from './routes/auth.js';
import forumRoutes from './routes/forum.js';
import socialRoutes from './routes/social.js';
import supportRoutes from './routes/support.js';
import contentRoutes from './routes/content.js';
import ownerRoutes from './routes/owner.js';

const COOKIE = 'tg_sid';

export function createApp(db, cfg) {
  const app = express();
  app.set('trust proxy', cfg.trustProxy);
  app.disable('x-powered-by');
  const mail = makeMailer(db, cfg);

  // ---------- context shared by route modules ----------
  const cache = new Map();
  const ctx = { db, cfg, mail };
  ctx.setting = async key => {
    const c = cache.get(key); if (c && c.t > Date.now()) return c.v;
    const r = await db.one('SELECT value FROM settings WHERE key=$1', [key]);
    const v = r ? r.value : DEFAULT_SETTINGS[key];
    cache.set(key, { v, t: Date.now() + 3000 }); return v;
  };
  ctx.setSetting = async (key, value, userId) => {
    await db.q('INSERT INTO settings (key,value,updated_by,updated_at) VALUES ($1,$2::jsonb,$3,now()) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_by=EXCLUDED.updated_by, updated_at=now()', [key, JSON.stringify(value), userId || null]);
    cache.delete(key);
  };
  ctx.secLog = (req, event, userId, meta = {}) => db.q('INSERT INTO security_logs (user_id,event,ip,ua,meta) VALUES ($1,$2,$3,$4,$5::jsonb)', [userId ?? req?.user?.id ?? null, event, req?.ip || null, (req?.get?.('user-agent') || '').slice(0, 300), JSON.stringify(meta)]).catch(() => {});
  ctx.audit = (req, action, targetType, targetId, before, after, reason) => db.q('INSERT INTO audit_logs (actor_id,actor_name,actor_role,action,target_type,target_id,ip,before,after,reason) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10)',
    [req.user?.id ?? null, req.user?.username ?? null, req.user ? (req.user.is_owner ? 'Owner' : req.user.roleNames.join(',') || 'Member') : null, action, targetType ?? null, targetId == null ? null : String(targetId), req.ip || null,
      before === undefined ? null : JSON.stringify(before), after === undefined ? null : JSON.stringify(after), reason || null]);
  ctx.notify = (userId, type, data = {}) => db.q('INSERT INTO notifications (user_id,type,data) VALUES ($1,$2,$3::jsonb)', [userId, type, JSON.stringify(data)]).catch(() => {});
  ctx.can = (user, perm) => !!user && (user.is_owner || user.perms.has(perm));
  ctx.createSession = async (userId, req) => {
    const days = await ctx.setting('session_days'); const tok = token(32), csrf = token(24);
    await db.q('INSERT INTO sessions (user_id,token_hash,csrf,ip,ua,expires_at) VALUES ($1,$2,$3,$4,$5, now() + ($6 || \' days\')::interval)', [userId, sha256(tok), csrf, req.ip, (req.get('user-agent') || '').slice(0, 300), String(days)]);
    return { tok, csrf };
  };
  ctx.setCookie = (res, tok) => res.cookie(COOKIE, tok, { httpOnly: true, sameSite: 'lax', secure: cfg.prod, path: '/', maxAge: 30 * 864e5 });

  // ---------- middleware ----------
  app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], imgSrc: ["'self'", 'data:', 'https:'], styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://accounts.google.com'], fontSrc: ["'self'", 'https://fonts.gstatic.com'], scriptSrc: ["'self'", 'https://challenges.cloudflare.com', 'https://accounts.google.com', 'https://cdnjs.cloudflare.com', ...(cfg.staticDir ? ["'unsafe-inline'"] : [])], scriptSrcAttr: cfg.staticDir ? ["'unsafe-inline'"] : ["'none'"], frameSrc: ['https://challenges.cloudflare.com', 'https://accounts.google.com'], connectSrc: ["'self'", 'https://accounts.google.com'], objectSrc: ["'none'"], frameAncestors: ["'none'"] } }, crossOriginResourcePolicy: { policy: 'same-site' } }));
  app.use(cookieParser());
  app.use('/api/uploads', express.raw({ type: ['image/png', 'image/jpeg', 'image/gif', 'image/webp'], limit: '64mb' }));
  app.use(express.json({ limit: '300kb' }));
  const globalLimit = rateLimit({ windowMs: 60_000, limit: 600, standardHeaders: true, legacyHeaders: false });
  app.get('/healthz', (req, res) => res.json({ ok: true }));
  app.use('/api', globalLimit);
  ctx.limit = (n, windowMs = 60_000) => rateLimit({ windowMs, limit: n, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many requests, slow down.' } });

  // session + user loading
  app.use('/api', wrap(async (req, res, next) => {
    req.user = null; req.session = null;
    const tok = req.cookies[COOKIE];
    if (tok) {
      const s = await db.one('SELECT * FROM sessions WHERE token_hash=$1 AND revoked_at IS NULL AND expires_at > now()', [sha256(tok)]);
      if (s) {
        const u = await db.one('SELECT * FROM users WHERE id=$1', [s.user_id]);
        if (u && u.status === 'active') {
          const rows = await db.q('SELECT r.id, r.name, r.color, r.is_staff, COALESCE(array_agg(rp.perm_key) FILTER (WHERE rp.perm_key IS NOT NULL), \'{}\') AS perms FROM user_roles ur JOIN roles r ON r.id=ur.role_id LEFT JOIN role_permissions rp ON rp.role_id=r.id WHERE ur.user_id=$1 GROUP BY r.id', [u.id]);
          const def = await db.q('SELECT r.id,r.name,r.color,r.is_staff, COALESCE(array_agg(rp.perm_key) FILTER (WHERE rp.perm_key IS NOT NULL), \'{}\') AS perms FROM roles r LEFT JOIN role_permissions rp ON rp.role_id=r.id WHERE r.is_default GROUP BY r.id');
          const all = [...def, ...rows];
          u.perms = new Set(all.flatMap(r => r.perms)); u.roleNames = all.map(r => r.name); u.roles = all; u.isStaff = u.is_owner || all.some(r => r.is_staff);
          u.banned = !!(u.banned_until && u.banned_until > new Date()); u.muted = !!(u.muted_until && u.muted_until > new Date());
          req.user = u; req.session = s;
          if (Date.now() - new Date(s.last_active_at).getTime() > 60_000) {
            const gap = Math.min(5, Math.max(1, Math.round((Date.now() - new Date(s.last_active_at).getTime()) / 60_000)));
            db.q(`INSERT INTO user_activity (user_id,day,minutes) VALUES ($1,CURRENT_DATE,$2) ON CONFLICT (user_id,day) DO UPDATE SET minutes=user_activity.minutes+$2`, [u.id, gap]).catch(() => {});
            db.q('UPDATE sessions SET last_active_at=now(), ip=$2 WHERE id=$1', [s.id, req.ip]).catch(() => {});
            db.q('UPDATE users SET last_active_at=now(), last_ip=$2 WHERE id=$1', [u.id, req.ip]).catch(() => {});
          }
        }
      }
    }
    next();
  }));
  // CSRF: Origin allowlist for every state-changing request, plus session-bound token when logged in
  app.use('/api', (req, res, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
    const origin = req.get('origin');
    if (origin && !cfg.origins.includes(origin) && origin !== `${req.protocol}://${req.get('host')}`) return next(new HttpError(403, 'Bad origin'));
    if (req.session && !(req.get('x-csrf-token') && safeEq(req.get('x-csrf-token'), req.session.csrf))) return next(new HttpError(403, 'Missing or invalid CSRF token'));
    next();
  });
  // maintenance mode
  app.use('/api', wrap(async (req, res, next) => {
    const m = await ctx.setting('maintenance');
    if (m?.on && !(req.user && (req.user.is_owner || req.user.perms.has('BYPASS_MAINTENANCE'))) && !/^\/(auth\/login|config|me|captcha)/.test(req.path))
      return res.status(503).json({ error: m.message || 'Maintenance', maintenance: true });
    next();
  }));

  // auth guards
  ctx.authed = (req, res, next) => req.user ? next() : next(new HttpError(401, 'Please log in'));
  // staff accounts must have 2FA switched on (setting require_admin_2fa) before they may use any staff route
  const need2fa = async req => (req.user.isStaff && !req.user.totp_enabled && await ctx.setting('require_admin_2fa')) ? new HttpError(403, 'Two-factor authentication is required for staff. Enable it in your account first.', { need2fa: true }) : null;
  ctx.need = perm => wrap(async (req, res, next) => { if (!req.user) return next(new HttpError(401, 'Please log in')); if (!ctx.can(req.user, perm)) return next(forbid(`Missing permission: ${perm}`)); const e = await need2fa(req); next(e || undefined); });
  ctx.staff = wrap(async (req, res, next) => { if (!req.user?.isStaff) return next(forbid('Staff only')); const e = await need2fa(req); next(e || undefined); });
  ctx.ownerOnly = wrap(async (req, res, next) => { if (!req.user?.is_owner) return next(forbid('Owner only')); const e = await need2fa(req); next(e || undefined); });
  ctx.reauth = wrap(async (req, res, next) => { // sensitive actions need a recent password (+2FA) confirmation
    const mins = await ctx.setting('owner_reauth_minutes');
    if (req.session?.reauth_at && Date.now() - new Date(req.session.reauth_at).getTime() < mins * 60_000) return next();
    next(new HttpError(401, 'Re-authentication required', { reauth: true }));
  });
  ctx.canWrite = (req, res, next) => { // banned / muted accounts can read, appeal and open tickets but not post
    if (req.user.force_reset) return next(forbid('You must change your password first'));
    if (req.user.banned) return next(forbid('Your account is banned'));
    if (req.user.muted) return next(forbid('You are timed out until ' + req.user.muted_until.toISOString()));
    next();
  };

  // admin panel access: staff need VIEW_ADMIN_PANEL to look, ADMIN_TAKE_ACTION to change anything (Owner always may)
  app.use(['/api/admin', '/api/staff'], (req, res, next) => {
    if (!req.user || req.user.is_owner) return next();
    const p = req.user.perms, read = ['GET', 'HEAD', 'OPTIONS'].includes(req.method);
    if (read ? (p.has('VIEW_ADMIN_PANEL') || p.has('ADMIN_TAKE_ACTION')) : p.has('ADMIN_TAKE_ACTION')) return next();
    next(forbid(read ? 'Missing permission: VIEW_ADMIN_PANEL' : 'Missing permission: ADMIN_TAKE_ACTION'));
  });

  // ---------- routes ----------
  app.use('/api', authRoutes(ctx));
  app.use('/api', forumRoutes(ctx));
  app.use('/api', socialRoutes(ctx));
  app.use('/api', supportRoutes(ctx));
  app.use('/api', contentRoutes(ctx));
  app.use('/api', ownerRoutes(ctx));
  app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));

  // public RSS feed of the newest threads (forums that are public and not hidden only)
  app.get(['/forums/-/index.rss', '/rss'], wrap(async (req, res) => {
    const x = v => String(v ?? '').replace(/[<>&"']/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;' }[c]));
    const rows = await db.q(`SELECT t.id, t.title, t.created_at, f.name AS forum, u.username FROM threads t JOIN forums f ON f.id=t.forum_id LEFT JOIN users u ON u.id=t.author_id WHERE t.deleted_at IS NULL AND t.approved AND f.visibility='public' AND NOT f.hidden ORDER BY t.created_at DESC LIMIT 30`);
    const name = await ctx.setting('site_name');
    res.type('application/rss+xml').send(`<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel><title>${x(name)}</title><link>${x(cfg.publicUrl)}</link><description>Latest threads</description>${rows.map(r => `<item><title>${x(r.title)}</title><link>${x(cfg.publicUrl)}/t/${r.id}</link><guid isPermaLink="false">thread-${r.id}</guid><category>${x(r.forum)}</category><author>${x(r.username || '')}</author><pubDate>${new Date(r.created_at).toUTCString()}</pubDate></item>`).join('')}</channel></rss>`);
  }));
  // ---- crawlable pages: /t/:id, /f/:id, sitemap.xml, robots.txt (the SPA itself uses #-routes that search engines cannot index) ----
  const ex = v => String(v ?? '').replace(/[<>&"']/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#39;' }[c]));
  const plain = v => String(v ?? '').replace(/\[(?:quote|spoiler)[^\]]*\]/gi, ' ').replace(/\[[^\]]*\]/g, '').replace(/\s+/g, ' ').trim();
  const BOT = /bot|crawl|spider|slurp|facebookexternalhit|discord|twitter|whatsapp|telegram|preview|embed|linkedin|pinterest|skype|google|bing/i;
  const PUB = "f.visibility='public' AND f.hidden=false AND f.archived=false";
  const page = (res, req, { title, desc, canon, body, spa, ld }) => {
    const redirect = BOT.test(req.get('user-agent') || '') ? '' : `<script>location.replace(${JSON.stringify(spa)})</script>`;
    res.set('Content-Security-Policy', "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src https: data:").type('html').send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${ex(title)}</title><meta name="description" content="${ex(desc)}"><link rel="canonical" href="${ex(canon)}"><meta property="og:type" content="article"><meta property="og:title" content="${ex(title)}"><meta property="og:description" content="${ex(desc)}"><meta property="og:url" content="${ex(canon)}">${ld ? `<script type="application/ld+json">${JSON.stringify(ld).replace(/</g, '\\u003c')}</script>` : ''}<style>body{font:16px/1.5 system-ui,sans-serif;max-width:860px;margin:24px auto;padding:0 16px;color:#1d2030}a{color:#2a6ebb}article{border:1px solid #ddd;border-radius:8px;padding:12px 16px;margin:12px 0}small{color:#666}</style></head><body>${body}${redirect}</body></html>`);
  };
  app.get('/t/:id', wrap(async (req, res) => {
    const id = parseInt(req.params.id, 10); if (!Number.isInteger(id)) return res.sendStatus(404);
    const t = await db.one(`SELECT t.id,t.title,t.created_at,f.name AS forum,f.id AS fid FROM threads t JOIN forums f ON f.id=t.forum_id WHERE t.id=$1 AND t.deleted_at IS NULL AND t.approved AND ${PUB}`, [id]); if (!t) return res.sendStatus(404);
    const posts = await db.q('SELECT p.body,p.created_at,u.username FROM posts p LEFT JOIN users u ON u.id=p.author_id WHERE p.thread_id=$1 AND p.deleted_at IS NULL AND NOT p.hidden ORDER BY p.created_at,p.id LIMIT 30', [id]);
    const site = await ctx.setting('site_name'), url = `${cfg.publicUrl}/t/${id}`, desc = plain(posts[0]?.body).slice(0, 160) || t.title;
    page(res, req, { title: `${t.title} | ${site}`, desc, canon: url, spa: `/#thread=${id}`, ld: { '@context': 'https://schema.org', '@type': 'DiscussionForumPosting', headline: t.title, datePublished: t.created_at, author: { '@type': 'Person', name: posts[0]?.username || 'Member' }, url },
      body: `<p><a href="/">${ex(site)}</a> › <a href="/f/${t.fid}">${ex(t.forum)}</a></p><h1>${ex(t.title)}</h1>${posts.map(p => `<article><small>${ex(p.username || 'Member')} · ${new Date(p.created_at).toISOString().slice(0, 10)}</small><p>${ex(plain(p.body)).slice(0, 4000)}</p></article>`).join('')}<p><a href="/#thread=${id}">Open in the forum</a></p>` });
  }));
  app.get('/f/:id', wrap(async (req, res) => {
    const id = parseInt(req.params.id, 10); if (!Number.isInteger(id)) return res.sendStatus(404);
    const f = await db.one(`SELECT f.id,f.name,f.description FROM forums f WHERE f.id=$1 AND ${PUB} AND f.link_url IS NULL`, [id]); if (!f) return res.sendStatus(404);
    const rows = await db.q('SELECT id,title FROM threads WHERE forum_id=$1 AND deleted_at IS NULL AND approved ORDER BY last_post_at DESC LIMIT 50', [id]), site = await ctx.setting('site_name');
    page(res, req, { title: `${f.name} | ${site}`, desc: f.description || `${f.name} on ${site}`, canon: `${cfg.publicUrl}/f/${id}`, spa: `/#f-${id}`, body: `<p><a href="/">${ex(site)}</a></p><h1>${ex(f.name)}</h1><p>${ex(f.description || '')}</p><ul>${rows.map(r => `<li><a href="/t/${r.id}">${ex(r.title)}</a></li>`).join('')}</ul>` });
  }));
  app.get('/sitemap.xml', wrap(async (req, res) => {
    const fs_ = await db.q(`SELECT f.id FROM forums f WHERE ${PUB} AND f.link_url IS NULL ORDER BY f.id`), ts = await db.q(`SELECT t.id,t.last_post_at FROM threads t JOIN forums f ON f.id=t.forum_id WHERE t.deleted_at IS NULL AND t.approved AND ${PUB} ORDER BY t.id DESC LIMIT 5000`);
    res.type('application/xml').send(`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>${ex(cfg.publicUrl)}/</loc></url>${fs_.map(f => `<url><loc>${ex(cfg.publicUrl)}/f/${f.id}</loc></url>`).join('')}${ts.map(t => `<url><loc>${ex(cfg.publicUrl)}/t/${t.id}</loc><lastmod>${new Date(t.last_post_at).toISOString()}</lastmod></url>`).join('')}</urlset>`);
  }));
  app.get('/robots.txt', wrap(async (req, res) => {
    const seo = await ctx.setting('seo'); const idx = !/noindex/i.test(seo?.robots || '');
    res.type('text/plain').send(`User-agent: *\n${idx ? 'Allow: /\nDisallow: /api/' : 'Disallow: /'}\nSitemap: ${cfg.publicUrl}/sitemap.xml\n`);
  }));
  // uploaded images: served with nosniff, never executable
  fs.mkdirSync(cfg.uploadDir, { recursive: true });
  app.get('/uploads/:f', (req, res) => {
    if (!/^[a-f0-9]{32}\.(png|jpg|gif|webp)$/.test(req.params.f)) return res.sendStatus(404);
    res.set('Cache-Control', 'public, max-age=31536000, immutable'); res.sendFile(path.resolve(cfg.uploadDir, req.params.f));
  });
  if (cfg.staticDir) { app.use(express.static(cfg.staticDir)); app.get(/^\/(?!api).*/, (q, r) => r.sendFile(path.resolve(cfg.staticDir, 'index.html'))); }

  app.use((err, req, res, next) => {
    if (err instanceof HttpError) return res.status(err.status).json({ error: err.message, ...(err.extra || {}) });
    if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Request too large' });
    if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON' });
    if (err.code === '23505') return res.status(409).json({ error: 'Already exists' });
    if (err.code === '23503') return res.status(409).json({ error: 'Referenced item missing or still in use' });
    if (err.code === '23514' || err.code === '22P02') return res.status(400).json({ error: 'Invalid value' });
    console.error(err); res.status(500).json({ error: 'Server error' });
  });
  return app;
}
