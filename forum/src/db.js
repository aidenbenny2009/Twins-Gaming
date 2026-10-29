// Unified DB adapter: real PostgreSQL via `pg`, or in-process PGlite (tests / zero-setup demo).
// API: db.q(sql, params) -> rows ; db.one(...) -> row|undefined ; db.tx(async t => ...) with t.q/t.one ; db.exec(sql) ; db.close()
export async function openDb({ url, memory } = {}) {
  let raw;
  if (memory || !url) {
    const { PGlite } = await import('@electric-sql/pglite');
    const pg = new PGlite();
    await pg.waitReady;
    raw = {
      q: async (s, p = []) => (await pg.query(s, p)).rows,
      exec: async s => { await pg.exec(s); },
      tx: async fn => pg.transaction(async t => fn(wrap(async (s, p = []) => (await t.query(s, p)).rows))),
      close: async () => pg.close(),
      kind: 'pglite',
    };
  } else {
    const pgmod = await import('pg');
    const types = pgmod.default.types;
    types.setTypeParser(20, v => parseInt(v, 10)); // bigint -> number (counts)
    const pool = new pgmod.default.Pool({ connectionString: url, max: 10 });
    raw = {
      q: async (s, p = []) => (await pool.query(s, p)).rows,
      exec: async s => { await pool.query(s); },
      tx: async fn => {
        const c = await pool.connect();
        try {
          await c.query('BEGIN');
          const r = await fn(wrap(async (s, p = []) => (await c.query(s, p)).rows));
          await c.query('COMMIT');
          return r;
        } catch (e) { await c.query('ROLLBACK').catch(() => {}); throw e; } finally { c.release(); }
      },
      close: async () => pool.end(),
      kind: 'pg',
    };
  }
  return wrap(raw.q, raw);
}
function wrap(q, raw = {}) {
  return { ...raw, q, one: async (s, p) => (await q(s, p))[0] };
}
