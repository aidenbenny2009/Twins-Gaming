import crypto from 'node:crypto';
import { Router } from 'express';
import { wrap, bad, str, int, HttpError, forbid } from '../util.js';
import { hashPassword, verifyPassword, passwordProblem, token, sha256, makeCaptcha, checkCaptcha, verifyTurnstile, newTotpSecret, totpVerify, totpUri, seal, unseal } from '../security.js';

const EMAIL = /^[^\s@]{1,64}@[^\s@]+\.[^\s@]{2,}$/;
export const userView = u => ({ id: u.id, username: u.username, display_name: u.display_name || u.username, avatar_url: u.avatar_url, banner_url: u.banner_url, is_owner: u.is_owner, created_at: u.created_at });

export default function (ctx) {
  const r = Router(), { db, cfg } = ctx;
  const DUMMY = hashPassword('dummy-password-for-timing');

  async function humanCheck(req, bodyCaptcha) {
    if (cfg.turnstileSecret) return verifyTurnstile(cfg.turnstileSecret, bodyCaptcha?.turnstile, req.ip);
    return checkCaptcha(cfg.secret, bodyCaptcha?.token, bodyCaptcha?.answer);
  }
  async function issueEmailToken(userId, purpose, hours) {
    const t = token(32);
    await db.q("INSERT INTO email_tokens (user_id,purpose,token_hash,expires_at) VALUES ($1,$2,$3, now() + ($4 || ' hours')::interval)", [userId, purpose, sha256(t), String(hours)]);
    return t;
  }
  async function consumeToken(t, purpose) {
    const row = await db.one('UPDATE email_tokens SET used_at=now() WHERE token_hash=$1 AND purpose=$2 AND used_at IS NULL AND expires_at > now() RETURNING user_id', [sha256(String(t || '')), purpose]);
    if (!row) throw bad('This link is invalid or has expired');
    return row.user_id;
  }

  r.get('/captcha', (req, res) => res.json(cfg.turnstileSecret ? { turnstile: cfg.turnstileSite } : makeCaptcha(cfg.secret)));

  r.post('/auth/register', ctx.limit(10, 3600_000), wrap(async (req, res) => {
    if (!(await ctx.setting('registration_open'))) throw forbid('Registration is closed');
    if ((await ctx.setting('captcha_on_register')) && !(await humanCheck(req, req.body.captcha))) throw bad('CAPTCHA failed', { captcha: true });
    const username = str(req.body.username, 'Username', { min: 3, max: 24 });
    if (!/^[A-Za-z0-9_]+$/.test(username)) throw bad('Username may only contain letters, numbers and _');
    const email = str(req.body.email, 'Email', { max: 254 }).toLowerCase();
    if (!EMAIL.test(email)) throw bad('Invalid email address');
    const pw = req.body.password; const pp = passwordProblem(pw, await ctx.setting('min_password_length')); if (pp) throw bad(pp);
    if (pw.toLowerCase().includes(username.toLowerCase())) throw bad('Password must not contain your username');
    const today = await db.one("SELECT count(*)::int n FROM users WHERE reg_ip=$1 AND created_at > now() - interval '1 day'", [req.ip]);
    if (today.n >= 5) { await ctx.secLog(req, 'register_ip_limit', null); throw new HttpError(429, 'Too many accounts from this network today'); }
    const needVerify = await ctx.setting('require_email_verification');
    let u;
    try {
      u = await db.one('INSERT INTO users (username,display_name,email,password_hash,email_verified,reg_ip,last_ip) VALUES ($1,$1,$2,$3,$4,$5,$5) RETURNING *', [username, email, await hashPassword(pw), !needVerify, req.ip]);
    } catch (e) { if (e.code === '23505') throw new HttpError(409, 'That username or email is already registered'); throw e; }
    await ctx.secLog(req, 'register', u.id);
    if (needVerify) { const t = await issueEmailToken(u.id, 'verify', 24); await ctx.mail.send(email, 'verify', { username, link: `${cfg.publicUrl}/verify?token=${t}` }); }
    res.status(201).json({ ok: true, needs_verification: needVerify });
  }));

  r.post('/auth/verify', ctx.limit(30, 3600_000), wrap(async (req, res) => {
    const uid = await consumeToken(req.body.token, 'verify');
    const u = await db.one('UPDATE users SET email_verified=true WHERE id=$1 RETURNING username,email', [uid]);
    await ctx.mail.send(u.email, 'welcome', { username: u.username }); await ctx.secLog(req, 'email_verified', uid);
    res.json({ ok: true });
  }));
  r.post('/auth/resend', ctx.limit(5, 3600_000), wrap(async (req, res) => {
    const email = str(req.body.email, 'Email', { max: 254 }).toLowerCase();
    const u = await db.one('SELECT * FROM users WHERE lower(email)=$1 AND NOT email_verified', [email]);
    if (u) { const t = await issueEmailToken(u.id, 'verify', 24); await ctx.mail.send(u.email, 'verify', { username: u.username, link: `${cfg.publicUrl}/verify?token=${t}` }); }
    res.json({ ok: true });
  }));

  r.post('/auth/login', ctx.limit(60, 15 * 60_000), wrap(async (req, res) => {
    const id = str(req.body.username, 'Username', { max: 254 }), pw = str(req.body.password, 'Password', { max: 200 });
    const [maxFail, lockMin, capAfter] = await Promise.all([ctx.setting('login_max_failures'), ctx.setting('login_lock_minutes'), ctx.setting('captcha_on_login_after')]);
    const recent = await db.one("SELECT count(*)::int n FROM login_attempts WHERE NOT success AND created_at > now() - interval '15 minutes' AND (ip=$1 OR lower(username)=lower($2))", [req.ip, id]);
    if (recent.n >= 30) throw new HttpError(429, 'Too many failed attempts. Try again later.');
    if (recent.n >= capAfter && !(await humanCheck(req, req.body.captcha))) throw new HttpError(401, 'Please complete the CAPTCHA', { captcha: true });
    const u = await db.one('SELECT * FROM users WHERE lower(username)=lower($1) OR lower(email)=lower($1)', [id]);
    const fail = async (why, userId) => {
      await db.q('INSERT INTO login_attempts (username,ip,success) VALUES ($1,$2,false)', [id.slice(0, 100), req.ip]);
      await ctx.secLog(req, 'login_failed', userId ?? null, { why, username: id.slice(0, 100) });
      if (userId) {
        const n = await db.one('UPDATE users SET failed_count=failed_count+1 WHERE id=$1 RETURNING failed_count', [userId]);
        if (n.failed_count >= maxFail) { await db.q("UPDATE users SET locked_until = now() + ($2 || ' minutes')::interval, failed_count=0 WHERE id=$1", [userId, String(lockMin)]); await ctx.secLog(req, 'account_locked', userId, { minutes: lockMin }); }
      }
      throw new HttpError(401, 'Invalid username or password', recent.n + 1 >= capAfter ? { captcha: true } : {});
    };
    if (!u) { await verifyPassword(pw, await DUMMY); return fail('unknown_user'); }
    if (u.locked_until && u.locked_until > new Date()) { await ctx.secLog(req, 'login_while_locked', u.id); throw new HttpError(423, 'Account temporarily locked after too many failed attempts. Try again later.'); }
    if (!(await verifyPassword(pw, u.password_hash))) return fail('bad_password', u.id);
    if (u.status !== 'active') throw forbid('This account is disabled');
    if (u.totp_enabled) {
      const code = String(req.body.totp || '').trim();
      if (!code) throw new HttpError(401, 'Two-factor code required', { needs_2fa: true });
      const secret = unseal(cfg.secret, u.totp_secret);
      let ok = secret && totpVerify(secret, code);
      if (!ok) { // recovery code?
        const hs = u.prefs?.recovery || [], h = sha256(code.toLowerCase());
        if (hs.includes(h)) { ok = true; await db.q("UPDATE users SET prefs = jsonb_set(prefs,'{recovery}',$2::jsonb) WHERE id=$1", [u.id, JSON.stringify(hs.filter(x => x !== h))]); await ctx.secLog(req, '2fa_recovery_used', u.id); }
      }
      if (!ok) return fail('bad_2fa', u.id);
    }
    if (!u.email_verified) throw new HttpError(403, 'Please confirm your email address first', { needs_verification: true });
    const { tok, csrf } = await ctx.createSession(u.id, req);
    await db.q('UPDATE users SET failed_count=0, locked_until=NULL, last_login_at=now(), last_ip=$2, last_active_at=now() WHERE id=$1', [u.id, req.ip]);
    await db.q('UPDATE sessions SET reauth_at=now() WHERE token_hash=$1', [sha256(tok)]);
    await db.q('INSERT INTO login_attempts (username,ip,success) VALUES ($1,$2,true)', [u.username, req.ip]);
    await ctx.secLog(req, 'login', u.id);
    ctx.setCookie(res, tok);
    res.json({ ok: true, csrf, force_reset: u.force_reset, user: userView(u) });
  }));

  // ---- Sign in with Google (needs GOOGLE_CLIENT_ID); the Google profile photo becomes the avatar ----
  const googleDefault = async credential => {
    const r = await fetch('https://oauth2.googleapis.com/tokeninfo?id_token=' + encodeURIComponent(credential), { signal: AbortSignal.timeout(8000) });
    if (!r.ok) throw new HttpError(401, 'Google sign-in failed'); return r.json();
  };
  const googleVerify = c => (cfg.googleVerify || googleDefault)(c);
  r.post('/auth/google', ctx.limit(30, 15 * 60_000), wrap(async (req, res) => {
    if (!cfg.googleClientId) throw new HttpError(404, 'Google sign-in is not configured');
    const cred = str(req.body.credential, 'Credential', { max: 4000 });
    const p = await googleVerify(cred).catch(() => null);
    if (!p || p.aud !== cfg.googleClientId || !p.sub || !p.email || !(p.email_verified === true || p.email_verified === 'true')) throw new HttpError(401, 'Google sign-in failed');
    const email = String(p.email).toLowerCase();
    let u = await db.one('SELECT * FROM users WHERE google_sub=$1', [p.sub]) || await db.one('SELECT * FROM users WHERE lower(email)=$1', [email]);
    if (!u) {
      if (!(await ctx.setting('registration_open'))) throw forbid('Registration is closed');
      let base = (email.split('@')[0].replace(/[^A-Za-z0-9_]/g, '').slice(0, 18) || 'player'); if (base.length < 3) base += '_tg';
      let name = base, i = 0; while (await db.one('SELECT 1 x FROM users WHERE lower(username)=lower($1)', [name])) name = base + (++i);
      u = await db.one('INSERT INTO users (username,display_name,email,password_hash,email_verified,reg_ip,last_ip,google_sub,avatar_url) VALUES ($1,$1,$2,$3,true,$4,$4,$5,$6) RETURNING *', [name, email, await hashPassword(crypto.randomBytes(24).toString('hex')), req.ip, p.sub, /^https:\/\//.test(p.picture || '') ? p.picture : null]);
      await ctx.secLog(req, 'register_google', u.id);
    } else {
      if (u.google_sub && u.google_sub !== p.sub) throw new HttpError(401, 'Google sign-in failed');
      await db.q('UPDATE users SET google_sub=$2, email_verified=true, avatar_url=CASE WHEN avatar_url IS NULL OR avatar_url LIKE \'https://%.googleusercontent.com/%\' THEN COALESCE($3,avatar_url) ELSE avatar_url END WHERE id=$1', [u.id, p.sub, /^https:\/\//.test(p.picture || '') ? p.picture : null]);
      u = await db.one('SELECT * FROM users WHERE id=$1', [u.id]);
    }
    if (u.status !== 'active') throw forbid('This account is disabled');
    if (u.totp_enabled) {
      const code = String(req.body.totp || '').trim(); if (!code) throw new HttpError(401, 'Two-factor code required', { needs_2fa: true });
      if (!totpVerify(unseal(cfg.secret, u.totp_secret) || '', code)) { await ctx.secLog(req, 'login_failed', u.id, { why: 'bad_2fa_google' }); throw new HttpError(401, 'Invalid 2FA code'); }
    }
    const { tok, csrf } = await ctx.createSession(u.id, req);
    await db.q('UPDATE users SET last_login_at=now(), last_ip=$2, last_active_at=now() WHERE id=$1', [u.id, req.ip]);
    await db.q('UPDATE sessions SET reauth_at=now() WHERE token_hash=$1', [sha256(tok)]);
    await ctx.secLog(req, 'login_google', u.id); ctx.setCookie(res, tok);
    res.json({ ok: true, csrf, user: userView(u) });
  }));

  r.post('/auth/logout', ctx.authed, wrap(async (req, res) => {
    await db.q('UPDATE sessions SET revoked_at=now() WHERE id=$1', [req.session.id]); res.clearCookie('tg_sid'); res.json({ ok: true });
  }));

  r.post('/auth/forgot', ctx.limit(5, 3600_000), wrap(async (req, res) => {
    const email = str(req.body.email, 'Email', { max: 254 }).toLowerCase();
    const u = await db.one('SELECT * FROM users WHERE lower(email)=$1 AND status=\'active\'', [email]);
    if (u) { const t = await issueEmailToken(u.id, 'reset', 1); await ctx.mail.send(u.email, 'reset', { username: u.username, link: `${cfg.publicUrl}/reset?token=${t}` }); await ctx.secLog(req, 'password_reset_requested', u.id); }
    res.json({ ok: true }); // identical response whether or not the account exists
  }));
  r.post('/auth/reset', ctx.limit(10, 3600_000), wrap(async (req, res) => {
    const pp = passwordProblem(req.body.password, await ctx.setting('min_password_length')); if (pp) throw bad(pp);
    const uid = await consumeToken(req.body.token, 'reset');
    await db.q('UPDATE users SET password_hash=$2, force_reset=false, failed_count=0, locked_until=NULL, email_verified=true WHERE id=$1', [uid, await hashPassword(req.body.password)]);
    await db.q('UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL', [uid]);
    await ctx.secLog(req, 'password_reset', uid); res.json({ ok: true });
  }));
  r.post('/auth/change-password', ctx.authed, ctx.limit(10, 3600_000), wrap(async (req, res) => {
    if (!(await verifyPassword(String(req.body.current || ''), req.user.password_hash))) { await ctx.secLog(req, 'change_password_failed'); throw new HttpError(401, 'Current password is wrong'); }
    const pp = passwordProblem(req.body.password, await ctx.setting('min_password_length')); if (pp) throw bad(pp);
    await db.q('UPDATE users SET password_hash=$2, force_reset=false WHERE id=$1', [req.user.id, await hashPassword(req.body.password)]);
    await db.q('UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND id<>$2 AND revoked_at IS NULL', [req.user.id, req.session.id]);
    await ctx.secLog(req, 'password_changed'); res.json({ ok: true });
  }));
  r.post('/auth/reauth', ctx.authed, ctx.limit(10, 15 * 60_000), wrap(async (req, res) => {
    const u = req.user;
    const ok = await verifyPassword(String(req.body.password || ''), u.password_hash) && (!u.totp_enabled || totpVerify(unseal(cfg.secret, u.totp_secret) || '', req.body.totp));
    if (!ok) { await ctx.secLog(req, 'reauth_failed'); throw new HttpError(401, 'Password' + (u.totp_enabled ? ' or 2FA code' : '') + ' is wrong'); }
    await db.q('UPDATE sessions SET reauth_at=now() WHERE id=$1', [req.session.id]); await ctx.secLog(req, 'reauth'); res.json({ ok: true });
  }));

  // ---- 2FA ----
  r.post('/2fa/setup', ctx.authed, wrap(async (req, res) => {
    if (req.user.totp_enabled) throw bad('2FA is already enabled');
    const s = newTotpSecret(); await db.q('UPDATE users SET totp_secret=$2 WHERE id=$1', [req.user.id, seal(cfg.secret, s)]);
    res.json({ secret: s, uri: totpUri(s, req.user.email, cfg.siteName) });
  }));
  r.post('/2fa/enable', ctx.authed, wrap(async (req, res) => {
    const s = req.user.totp_secret && unseal(cfg.secret, req.user.totp_secret);
    if (!s || !totpVerify(s, req.body.code)) throw bad('That code is not correct');
    const codes = Array.from({ length: 8 }, () => token(6).toLowerCase().replace(/[-_]/g, 'x'));
    await db.q("UPDATE users SET totp_enabled=true, prefs = jsonb_set(prefs,'{recovery}',$2::jsonb,true) WHERE id=$1", [req.user.id, JSON.stringify(codes.map(c => sha256(c)))]);
    await ctx.secLog(req, '2fa_enabled'); res.json({ ok: true, recovery_codes: codes });
  }));
  r.post('/2fa/disable', ctx.authed, wrap(async (req, res) => {
    const u = req.user; if (!u.totp_enabled) throw bad('2FA is not enabled');
    if (!(await verifyPassword(String(req.body.password || ''), u.password_hash)) || !totpVerify(unseal(cfg.secret, u.totp_secret) || '', req.body.code)) throw new HttpError(401, 'Password or code is wrong');
    await db.q("UPDATE users SET totp_enabled=false, totp_secret=NULL, prefs = prefs - 'recovery' WHERE id=$1", [u.id]); await ctx.secLog(req, '2fa_disabled'); res.json({ ok: true });
  }));

  // ---- me / sessions / config ----
  r.get('/me', wrap(async (req, res) => {
    const u = req.user; if (!u) return res.json({ user: null });
    res.json({ csrf: req.session.csrf, user: { ...userView(u), email: u.email, email_verified: u.email_verified, totp_enabled: u.totp_enabled, force_reset: u.force_reset, banned_until: u.banned_until, muted_until: u.muted_until, ban_reason: u.banned ? u.ban_reason : null, roles: u.roles.map(({ id, name, color, is_staff }) => ({ id, name, color, is_staff })), is_staff: u.isStaff, perms: u.is_owner ? ['*'] : [...u.perms], prefs: { ...u.prefs, recovery: undefined }, bio: u.bio, signature: u.signature, social: u.social } });
  }));
  r.get('/me/sessions', ctx.authed, wrap(async (req, res) => {
    const rows = await db.q('SELECT id, ip, ua, created_at, last_active_at, expires_at FROM sessions WHERE user_id=$1 AND revoked_at IS NULL AND expires_at>now() ORDER BY last_active_at DESC', [req.user.id]);
    res.json(rows.map(s => ({ ...s, current: s.id === req.session.id })));
  }));
  r.delete('/me/sessions/:id', ctx.authed, wrap(async (req, res) => { await db.q('UPDATE sessions SET revoked_at=now() WHERE id=$1 AND user_id=$2', [int(req.params.id), req.user.id]); res.json({ ok: true }); }));
  r.post('/me/sessions/revoke-others', ctx.authed, wrap(async (req, res) => { await db.q('UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND id<>$2 AND revoked_at IS NULL', [req.user.id, req.session.id]); res.json({ ok: true }); }));
  r.get('/me/security', ctx.authed, wrap(async (req, res) => res.json(await db.q('SELECT event, ip, created_at FROM security_logs WHERE user_id=$1 ORDER BY id DESC LIMIT 50', [req.user.id]))));
  return r;
}
