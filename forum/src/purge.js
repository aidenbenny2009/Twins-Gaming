export async function purge(db, setting) {
  const a = await setting('retention_login_attempts_days'), s = await setting('retention_security_logs_days');
  const out = {};
  out.login_attempts = (await db.q("WITH d AS (DELETE FROM login_attempts WHERE created_at < now() - ($1 || ' days')::interval RETURNING 1) SELECT count(*)::int n FROM d", [String(a)]))[0].n;
  out.security_logs = (await db.q("WITH d AS (DELETE FROM security_logs WHERE created_at < now() - ($1 || ' days')::interval RETURNING 1) SELECT count(*)::int n FROM d", [String(s)]))[0].n;
  out.sessions = (await db.q("WITH d AS (DELETE FROM sessions WHERE expires_at < now() - interval '7 days' OR revoked_at < now() - interval '7 days' RETURNING 1) SELECT count(*)::int n FROM d"))[0].n;
  out.email_tokens = (await db.q("WITH d AS (DELETE FROM email_tokens WHERE expires_at < now() - interval '2 days' RETURNING 1) SELECT count(*)::int n FROM d"))[0].n;
  out.visitors = (await db.q("WITH d AS (DELETE FROM visitors WHERE day < current_date - 90 RETURNING 1) SELECT count(*)::int n FROM d"))[0].n;
  return out;
}
