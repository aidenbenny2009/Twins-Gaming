import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const here = path.dirname(fileURLToPath(import.meta.url));

export const PERMS = {
  VIEW_ADMIN_PANEL: 'See the admin panel (read-only view)', ADMIN_TAKE_ACTION: 'Take action in the admin panel (punish, edit, change)',
  VIEW_FORUM: 'View forums', CREATE_THREAD: 'Create threads', REPLY: 'Reply to threads', EDIT_OWN_POST: 'Edit own posts', DELETE_OWN_POST: 'Delete own posts',
  UPLOAD: 'Upload images', REACT: 'React to posts', SEND_DM: 'Send private messages', REPORT: 'Report content',
  EDIT_ANY_POST: 'Edit any post', DELETE_ANY_POST: 'Delete/restore any post', PIN_THREAD: 'Pin threads', LOCK_THREAD: 'Lock threads', MOVE_THREAD: 'Move threads',
  MERGE_THREAD: 'Merge threads', SPLIT_THREAD: 'Split threads', MARK_SOLVED: 'Mark any thread solved', ARCHIVE_THREAD: 'Archive threads', FEATURE_THREAD: 'Feature threads',
  APPROVE_CONTENT: 'Approve moderated content', BULK_MODERATE: 'Bulk moderation', VIEW_EDIT_HISTORY: 'View post edit history', VIEW_HIDDEN: 'View hidden/deleted content',
  HANDLE_REPORTS: 'Handle reports',
  WARN_USER: 'Warn users', TIMEOUT_USER: 'Time out users', BAN_USER: 'Ban/unban users', VIEW_IP: 'View IP addresses', VIEW_AUDIT: 'View audit log',
  VIEW_SECURITY: 'View security dashboard', MANAGE_ANNOUNCEMENTS: 'Manage announcements', MANAGE_RULES: 'Manage rules', MANAGE_CONTENT: 'Manage pages, links, navigation, SEO',
  MANAGE_FORUMS: 'Manage categories/forums/prefixes', MANAGE_USERS: 'Manage user accounts', VIEW_ANALYTICS: 'View analytics', MANAGE_MEDIA: 'Manage media library',
  BYPASS_MAINTENANCE: 'Access site during maintenance', VIEW_MEMBERS: 'View member list', VIEW_RULE_REVISIONS: 'View rule revision history',
};
const BASE = ['VIEW_FORUM', 'CREATE_THREAD', 'REPLY', 'EDIT_OWN_POST', 'DELETE_OWN_POST', 'UPLOAD', 'REACT', 'SEND_DM', 'REPORT', 'VIEW_MEMBERS'];
const MOD = [...BASE, 'VIEW_ADMIN_PANEL', 'ADMIN_TAKE_ACTION', 'EDIT_ANY_POST', 'DELETE_ANY_POST', 'PIN_THREAD', 'LOCK_THREAD', 'MOVE_THREAD', 'MERGE_THREAD', 'SPLIT_THREAD', 'MARK_SOLVED', 'ARCHIVE_THREAD', 'APPROVE_CONTENT', 'BULK_MODERATE', 'VIEW_EDIT_HISTORY', 'VIEW_HIDDEN', 'HANDLE_REPORTS', 'WARN_USER', 'TIMEOUT_USER', 'BYPASS_MAINTENANCE'];
const ADMIN = [...MOD, 'FEATURE_THREAD', 'BAN_USER', 'VIEW_AUDIT', 'MANAGE_ANNOUNCEMENTS', 'MANAGE_RULES', 'MANAGE_FORUMS', 'MANAGE_MEDIA', 'VIEW_ANALYTICS', 'VIEW_SECURITY'];

export const DEFAULT_SETTINGS = {
  site_name: 'TWINS GAMING', tagline: 'Community platform by Twins Gaming', registration_open: true, require_email_verification: true, captcha_on_register: true,
  captcha_on_login_after: 3, min_password_length: 10, max_upload_mb: 12, flood_max_per_minute: 6, duplicate_window_minutes: 10, autopunish_mute_minutes: 15,
  login_max_failures: 5, login_lock_minutes: 15, session_days: 14, owner_reauth_minutes: 10, maintenance: { on: false, message: 'We are updating the forum. Back soon!' },
  retention_login_attempts_days: 30, retention_security_logs_days: 180, rules_revisions_public: false, theme: { default: 'dark', accent: '#ffd000', custom_css: '' },
  seo: { title: 'TWINS GAMING Community', description: 'The official TWINS GAMING community forum.', og_image: '', robots: 'index,follow' },
  threads_disabled: false, require_admin_2fa: true, rss_url: '', footer_a: '', footer_b: '', footer_since: '', admin_signature: '', banner_url: '', admin_daily_minutes: 120, analytics_enabled: true, honor_dnt: true, reaction_types: ['like', 'dislike', 'love', 'haha', 'wow', 'sad', 'angry'],
};
const TEXT = {
  hero_title: ['Home', 'Welcome to TWINS GAMING'], hero_sub: ['Home', 'The official community of Twins Gaming.'], footer_copy: ['Footer', '© 2009 Twins Gaming Ltd.'],
  register_notice: ['Auth', 'By registering you agree to the Terms and Rules.'], banned_notice: ['Auth', 'Your account is restricted. You may submit an appeal.'],
};
const TPL = {
  verify: ['Confirm your {{site}} account', 'Hi {{username}},<br>Confirm your email: <a href="{{link}}">{{link}}</a><br>This link expires in 24 hours.', 'Hi {{username}}, confirm your email: {{link}} (expires in 24h)'],
  reset: ['Reset your {{site}} password', 'Hi {{username}},<br>Reset your password: <a href="{{link}}">{{link}}</a><br>This link expires in 1 hour. Ignore this email if it was not you.', 'Hi {{username}}, reset your password: {{link}} (expires in 1h)'],
  welcome: ['Welcome to {{site}}', 'Welcome {{username}}! Your email is confirmed.', 'Welcome {{username}}! Your email is confirmed.'],
  sanction: ['Account notice from {{site}}', 'Hi {{username}},<br>A {{type}} was applied to your account.<br>Reason: {{reason}}<br>Until: {{until}}', 'Hi {{username}}, a {{type}} was applied. Reason: {{reason}}. Until: {{until}}'],
  announcement: ['{{title}}', '{{title}}<br>{{url}}', '{{title}} {{url}}'],
};
const STATUS = {
  report: [['Open', '#ffd000'], ['In review', '#4aa3ff'], ['Resolved', '#3ecf8e', 1], ['Rejected', '#9aa0b4', 1]],
};

export async function applySchema(db) {
  const has = await db.one("SELECT to_regclass('public.users') AS t");
  if (has && has.t) return false;
  await db.exec(fs.readFileSync(path.join(here, '..', 'sql', 'schema.sql'), 'utf8'));
  return true;
}
export async function migrate(db) {
  await db.exec(`ALTER TABLE prefixes ADD COLUMN IF NOT EXISTS advanced BOOLEAN NOT NULL DEFAULT FALSE;
CREATE TABLE IF NOT EXISTS name_changes (id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE, old_name TEXT NOT NULL, new_name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', note TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), decided_by INT REFERENCES users(id), decided_at TIMESTAMPTZ);
CREATE INDEX IF NOT EXISTS name_changes_status ON name_changes(status, created_at);
ALTER TABLE forums ADD COLUMN IF NOT EXISTS link_url TEXT; ALTER TABLE forums ADD COLUMN IF NOT EXISTS page_route TEXT; ALTER TABLE forums ADD COLUMN IF NOT EXISTS is_archive BOOLEAN NOT NULL DEFAULT false; ALTER TABLE forums ADD COLUMN IF NOT EXISTS thread_roles JSONB; ALTER TABLE forums ADD COLUMN IF NOT EXISTS reply_roles JSONB;
ALTER TABLE users ADD COLUMN IF NOT EXISTS google_sub TEXT;
ALTER TABLE reports ADD COLUMN IF NOT EXISTS priority TEXT NOT NULL DEFAULT 'normal'; ALTER TABLE forums ADD COLUMN IF NOT EXISTS fields JSONB; ALTER TABLE threads ADD COLUMN IF NOT EXISTS fields JSONB; ALTER TABLE categories ADD COLUMN IF NOT EXISTS visibility TEXT NOT NULL DEFAULT 'all'; ALTER TABLE categories ADD COLUMN IF NOT EXISTS color TEXT; ALTER TABLE categories ADD COLUMN IF NOT EXISTS collapsed BOOLEAN NOT NULL DEFAULT FALSE; ALTER TABLE categories ADD COLUMN IF NOT EXISTS no_threads BOOLEAN NOT NULL DEFAULT FALSE;
CREATE UNIQUE INDEX IF NOT EXISTS users_google_sub ON users(google_sub) WHERE google_sub IS NOT NULL;
CREATE TABLE IF NOT EXISTS contact_messages (id SERIAL PRIMARY KEY, user_id INT REFERENCES users(id) ON DELETE SET NULL, name TEXT NOT NULL, email TEXT NOT NULL, subject TEXT NOT NULL, message TEXT NOT NULL, ip TEXT, is_read BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS user_activity (user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE, day DATE NOT NULL, minutes INT NOT NULL DEFAULT 0, PRIMARY KEY (user_id, day));`);
  for (const [n, c, t] of [['On consideration','#f5a623','#000000'],['Reviewed','#8bd17c','#000000'],['Rejected','#7a7a7a','#ffffff'],['For curator of the project','#d00000','#ffffff'],['IMPORTANT','#e00000','#ffffff']]) await db.q('INSERT INTO prefixes (name,color,text_color) SELECT $1,$2,$3 WHERE NOT EXISTS (SELECT 1 FROM prefixes WHERE name=$1)', [n, c, t]);
  await db.q(`INSERT INTO prefixes (name,color,text_color) SELECT 'Pending review','#ffc21a','#000000' WHERE NOT EXISTS (SELECT 1 FROM prefixes WHERE name='Pending review')`);
  await db.q(`UPDATE forums SET allowed_prefixes=(SELECT jsonb_build_array(id) FROM prefixes WHERE name='Pending review') WHERE name ILIKE '%applic%' AND allowed_prefixes IS NULL`);
  await db.q("UPDATE forums SET is_archive=true WHERE name ILIKE '%Archive' AND NOT is_archive");
  // Support section removed: drop its empty forums/category and the ticket/appeal/application permissions
  await db.q("DELETE FROM forums WHERE page_route IN ('apps','tickets','appeal') AND NOT EXISTS (SELECT 1 FROM threads t WHERE t.forum_id=forums.id)");
  await db.q("DELETE FROM categories WHERE name='Support & Applications' AND NOT EXISTS (SELECT 1 FROM forums f WHERE f.category_id=categories.id)");
  await db.q("DELETE FROM permissions WHERE key IN ('CREATE_TICKET','SUBMIT_APPLICATION','SUBMIT_APPEAL','HANDLE_TICKETS','HANDLE_APPLICATIONS','HANDLE_APPEALS')");
  await db.q("INSERT INTO permissions (key, description) VALUES ('VIEW_ADMIN_PANEL','See the admin panel (read-only view)'),('ADMIN_TAKE_ACTION','Take action in the admin panel (punish, edit, change)') ON CONFLICT DO NOTHING");
  // existing staff roles keep working: give them both new permissions once
  await db.q("INSERT INTO role_permissions SELECT r.id, k.key FROM roles r, (VALUES ('VIEW_ADMIN_PANEL'),('ADMIN_TAKE_ACTION')) k(key) WHERE r.is_staff AND NOT EXISTS (SELECT 1 FROM settings WHERE key='admin_perms_migrated') ON CONFLICT DO NOTHING");
  await db.q("INSERT INTO settings (key,value) VALUES ('admin_perms_migrated','true'::jsonb) ON CONFLICT DO NOTHING");
  await db.q(`UPDATE settings SET value=$1::jsonb WHERE key='reaction_types' AND value=$2::jsonb`, [JSON.stringify(DEFAULT_SETTINGS.reaction_types), JSON.stringify(['like', 'love', 'haha', 'wow', 'sad'])]);
}
export async function seed(db, brand = {}) {
  await migrate(db);
  for (const [k, d] of Object.entries(PERMS)) await db.q('INSERT INTO permissions (key, description) VALUES ($1,$2) ON CONFLICT DO NOTHING', [k, d]);
  if (!(await db.one('SELECT 1 x FROM roles LIMIT 1'))) {
    const defs = [['Member', '#cfd3e6', false, true, BASE, 10], ['Moderator', '#3ecf8e', true, false, MOD, 20], ['Admin', '#ff5c5c', true, false, ADMIN, 30]];
    for (const [name, color, staff, def, perms, sort] of defs) {
      const r = await db.one('INSERT INTO roles (name,color,is_staff,is_default,sort) VALUES ($1,$2,$3,$4,$5) RETURNING id', [name, color, staff, def, sort]);
      for (const p of perms) await db.q('INSERT INTO role_permissions VALUES ($1,$2)', [r.id, p]);
    }
  }
  for (const [k, v] of Object.entries(DEFAULT_SETTINGS)) await db.q('INSERT INTO settings (key,value) VALUES ($1,$2::jsonb) ON CONFLICT DO NOTHING', [k, JSON.stringify(v)]);
  for (const [k, [g, v]] of Object.entries(TEXT)) await db.q('INSERT INTO content_texts (key,label,grp,value) VALUES ($1,$1,$2,$3) ON CONFLICT DO NOTHING', [k, g, v]);
  for (const [k, [s, h, t]] of Object.entries(TPL)) await db.q('INSERT INTO email_templates (key,subject,body_html,body_text) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING', [k, s, h, t]);
  for (const [scope, list] of Object.entries(STATUS)) {
    let i = 0; for (const [name, color, closed] of list) await db.q('INSERT INTO statuses (scope,name,color,sort,is_closed) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING', [scope, name, color, i++, !!closed]);
  }
  if (!(await db.one('SELECT 1 x FROM categories LIMIT 1'))) {
    const c1 = await db.one("INSERT INTO categories (name,sort) VALUES ('Community',1) RETURNING id");
    const c2 = await db.one("INSERT INTO categories (name,sort) VALUES ('Help',2) RETURNING id");
    for (const [c, n, d, s, vis] of [[c1.id, 'Announcements', 'Official news from Twins Gaming', 1, 'public'], [c1.id, 'General Discussion', 'Talk about anything', 2, 'public'], [c1.id, 'Gaming', 'Games, clips and tips', 3, 'public'], [c2.id, 'Help & Questions', 'Ask the community', 1, 'public'], [c2.id, 'Staff Room', 'Staff only', 9, 'staff']])
      await db.q('INSERT INTO forums (category_id,name,description,sort,visibility,thread_perm) VALUES ($1,$2,$3,$4,$5,$6)', [c, n, d, s, vis, n === 'Announcements' ? 'EDIT_ANY_POST' : 'CREATE_THREAD']);
    for (const [n, col, tc] of [['Question', '#4aa3ff', '#000000'], ['Guide', '#3ecf8e', '#000000'], ['Clip', '#7c5cff', '#ffffff']]) await db.q('INSERT INTO prefixes (name,color,text_color) VALUES ($1,$2,$3)', [n, col, tc]);
    await db.q("INSERT INTO rule_sections (name,sort) VALUES ('Forum rules',1)");
    await db.q("INSERT INTO badges (name,description,points) VALUES ('Welcome','Joined the community',1)");
  }
  if (!(await db.one('SELECT 1 x FROM links LIMIT 1'))) {
    const L = [['Website', brand.website || 'https://twinsgamingoffical.netlify.app/', 'globe'], ['Instagram', brand.instagram || 'https://www.instagram.com/mr.aidenbenny?igsh=dzE5N3RlOWFrZDRv', 'instagram'],
      ['YouTube', brand.youtube || 'https://www.youtube.com/@TwinsGaming2009', 'youtube'], ['Discord', brand.discord || 'https://discord.gg/fR4ZmKYaHH', 'discord']];
    let i = 0; for (const loc of ['header', 'footer']) for (const [n, u, ic] of L) await db.q('INSERT INTO links (name,url,icon,location,sort) VALUES ($1,$2,$3,$4,$5)', [n, u, ic, loc, i++]);
  }
  if (!(await db.one('SELECT 1 x FROM nav_items LIMIT 1'))) {
    let i = 0; for (const [l, u] of [['Forums', '/forums'], ['Members', '/members'], ['Rules', '/rules'], ['Help', '/help']]) await db.q("INSERT INTO nav_items (menu,label,url,sort) VALUES ('header',$1,$2,$3)", [l, u, i++]);
  }
  // forum for admin/staff applications: only the "Pending review" prefix may be used there
  if (!(await db.one("SELECT 1 x FROM forums WHERE name ILIKE '%applic%'"))) {
    const cat = await db.one('SELECT id FROM categories ORDER BY sort,id LIMIT 1');
    if (cat) await db.q("INSERT INTO forums (category_id,name,description,sort,visibility,thread_perm) VALUES ($1,'Admin applications','Apply to join the Twins Gaming admin team',9,'public','CREATE_THREAD')", [cat.id]);
  }
  await db.q(`UPDATE forums SET allowed_prefixes=(SELECT jsonb_build_array(id) FROM prefixes WHERE name='Pending review') WHERE name ILIKE '%applic%' AND allowed_prefixes IS NULL`);
  // ---- forum structure (idempotent, matched by name) ----
  const STAFF = 'EDIT_ANY_POST';
  async function cat(name, sort) { let c = await db.one('SELECT id FROM categories WHERE name=$1', [name]); if (!c) c = await db.one("INSERT INTO categories (name,sort) VALUES ($1,$2) RETURNING id", [name, sort]); return c.id; }
  async function forum(c, name, sort, parent = null, perm = 'CREATE_THREAD', desc = '') {
    let f = await db.one('SELECT id FROM forums WHERE name=$1 AND COALESCE(parent_id,0)=COALESCE($2::int,0)', [name, parent]);
    if (!f) f = await db.one("INSERT INTO forums (category_id,parent_id,name,description,sort,visibility,thread_perm) VALUES ($1,$2,$3,$4,$5,'public',$6) RETURNING id", [c, parent, name, desc, sort, perm]);
    return f.id;
  }
  const c2 = await cat('Twins Gaming', 2);
  const faq = await forum(c2, 'Frequently asked questions (FAQ)', 1); await forum(c2, 'FAQ', 1, faq);
  await forum(c2, 'Donate services', 2);
  const tech = await forum(c2, 'Technical section', 3); await forum(c2, '🗄️ Archive', 1, tech); await forum(c2, 'Technical Application', 2, tech);
  const c3 = await cat('Forums', 3);
  await forum(c3, 'Complaints', 1);
  const ca = await forum(c3, 'Complaints about administrators and assistants', 2); await forum(c3, '🗄️ Archive', 1, ca);
  const cm = await forum(c3, 'Complaints about Members', 3); await forum(c3, '🗄️ Archive', 1, cm);
  const ccr = await forum(c3, 'Community Rules', 0, null, STAFF);
  if (!(await db.one("SELECT 1 x FROM forums WHERE link_url IS NOT NULL"))) await db.q("INSERT INTO forums (category_id,name,sort,visibility,thread_perm,link_url) VALUES ($1,'Connect to the official channel in Discord',9,'public','CREATE_THREAD',$2)", [c2, 'https://discord.gg/fR4ZmKYaHH']);
  await db.q("UPDATE forums SET is_archive=true WHERE name ILIKE '%Archive' AND NOT is_archive");
}
