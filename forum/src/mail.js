import { esc } from './util.js';
// Sends real email when SMTP_URL is set (and nodemailer installed); otherwise records to the `outbox` table
// with status 'logged' so nothing is silently lost and the Owner can see what would have been sent.
export function makeMailer(db, cfg) {
  let transport = null;
  const ready = (async () => {
    if (!cfg.smtpUrl) return;
    try { const nm = await import('nodemailer'); transport = nm.default.createTransport(cfg.smtpUrl); } catch (e) { console.error('[mail] SMTP unavailable:', e.message); }
  })();
  const fill = (t, vars, html) => t.replace(/\{\{\s*(\w+)\s*\}\}/g, (_, k) => (vars[k] == null ? '' : html ? esc(vars[k]) : String(vars[k])));
  async function send(to, key, vars = {}) {
    await ready;
    const tpl = await db.one('SELECT * FROM email_templates WHERE key=$1', [key]);
    if (!tpl || !tpl.enabled) return { skipped: true };
    const v = { site: cfg.siteName, url: cfg.publicUrl, ...vars };
    const subject = fill(tpl.subject, v, false), html = fill(tpl.body_html, v, true), text = fill(tpl.body_text, v, false);
    let status = 'logged', error = null;
    if (transport) {
      try { await transport.sendMail({ from: cfg.mailFrom, to, subject, html, text }); status = 'sent'; } catch (e) { status = 'failed'; error = String(e.message).slice(0, 300); }
    }
    await db.q('INSERT INTO outbox (to_email, template, subject, body_html, status, error) VALUES ($1,$2,$3,$4,$5,$6)', [to, key, subject, html, status, error]);
    return { status };
  }
  return { send };
}
