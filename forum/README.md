# TWINS GAMING forum — backend

Node 22 + Express + PostgreSQL. No organization/faction/government systems.

## Run
```
cp .env.example .env            # set SESSION_SECRET, DATABASE_URL, SMTP_URL
npm ci
npm run migrate                 # creates schema + seed data
OWNER_PASSWORD='...' npm run create-owner -- Aiden you@example.com
npm start
```
Without `DATABASE_URL` it runs on a temporary in-memory Postgres (PGlite) for trying it out. Docker: `docker compose up`.
Tests: `npm test` (38 end-to-end tests on PGlite).

## What is implemented (all server-side enforced)
- **Accounts**: scrypt passwords, email verification, reset, change password, signed CAPTCHA (or Turnstile), per-IP registration cap.
- **Security**: failed-login log, CAPTCHA after N failures, account lockout, IP throttle, TOTP 2FA + recovery codes, DB sessions (list/revoke/force logout), CSRF (Origin + session token), re-auth for dangerous Owner actions, IP search, security dashboard, audit log (CSV export), retention purge.
- **Roles**: exactly one Owner (DB-enforced); 46 permissions; custom roles edited by the Owner only; staff can't act on staff/Owner.
- **Forum**: categories/forums/sub-forums/prefixes, threads, posts, quotes, @mentions, reactions, bookmarks, watch, solved/pin/lock/archive/feature, approval queue, soft delete, **edit history**, **move/merge/split/bulk moderation**, full-text search.
- **Support**: reports, tickets (+image attachments, staff reply email), applications (dynamic fields incl. file upload), appeals, editable statuses, history and internal notes.
- **Discipline**: warn/timeout/ban/unban with duration, reasons, evidence; flood/duplicate auto-punish (logged even for admins).
- **CMS**: pages, links, navigation, SEO, theme (+Owner-only custom CSS), texts, **email template editor**, rules with revision history (Owner decides who can see it), announcements (+notify/email), media library.
- **Owner**: users, roles, settings, maintenance mode, live dashboard (SSE at `/api/admin/live`), analytics (privacy-friendly, DNT honoured), export, **backup / restore** (JSON, re-auth + typed confirmation).
- Uploads: magic-byte validated, size limit editable (default 12 MB).

## Not included / your responsibility
- The browser front-end (`twins-forum.html`) is still the localStorage prototype; it is not wired to this API yet.
- Backups contain password hashes: keep `BACKUP_DIR` private. Uploaded images are not part of the JSON backup; back up `UPLOAD_DIR` too.
- Set `TRUST_PROXY` correctly behind a reverse proxy, serve over HTTPS, and use a real SMTP server (without `SMTP_URL`, emails are only stored in the `outbox` table).
- The Discord link seeded from your brief (`https://discord.gg/Twins_Gaming/fR4ZmKYaHH`) looks malformed; correct it in Owner → Links.


## Front end (connected)
`public/index.html` is the forum UI. When the server starts it serves that file, and the page detects `/api` on the same origin and switches to **online mode**:
register (CAPTCHA + email confirmation), log in (2FA code if enabled), forums/threads/replies, likes, bookmarks, watch, pin/lock/archive/delete from your real permissions, profile data, members and logout all use the API and PostgreSQL.
Without a server the same file still opens in prototype mode (data kept in the browser only).
Not yet wired in the UI (the API for them exists): applications, appeals, tickets, DMs, notifications, reports, and the Owner panel tabs. Use the API directly or extend the page.
Note: the page uses inline scripts, so when `public/` is served the CSP allows `'unsafe-inline'` scripts. All user content is escaped before display.
Confirmation mail: set `SMTP_URL`, otherwise links land in the `outbox` table (Owner > outbox API).

### v18 additions
- Username changes are requests: members ask from Account details, an Owner/Admin approves or rejects under Owner → Name changes (`/api/me/username-change`, `/api/admin/name-changes`).
- Reactions: like, dislike, love, haha, wow, sad, angry (`reaction_types` setting; existing databases are upgraded automatically on start). `GET /api/posts/:id/reactions` lists who reacted.
- `npm run migrate` / server start adds new tables and columns to an existing database automatically.

### Admin panel (v20)
Open `/admin` (or the ⚙ ADMIN PANEL link, shown to staff only). Staff log in again there with password (+2FA code). The menu only shows sections the account's permissions allow; the level shown is derived from how many sections that account can use (Owner = 5). Connected to the server: Home, List of administrators (`/api/admin/staff`), Search member, Member Punishment, All logs, Security log, Name changes. Other sections still edit browser-only data until wired.

## Sign in with Google (optional)
1. In Google Cloud Console create an OAuth client ID (type: Web application) and add your site URL under "Authorized JavaScript origins".
2. Set `GOOGLE_CLIENT_ID=<that id>` in your environment and restart. A "Continue with Google" button then appears on the login page.
3. The first Google login creates an account (or links to the account with the same verified email) and uses the Google profile photo as the avatar. Accounts with 2FA still ask for the authenticator code.

## Forum structure (admin)
Admin → Forums & categories saves to the database: categories, nested forums (any depth), link rows (`link_url`), page rows (`page_route`: apps / tickets / appeals / rules), Archive sections (`is_archive`), drag-and-drop ordering (`PUT /api/admin/structure/order`), and per-forum posting rules (`thread_perm` / `reply_perm`: a permission name, `VERIFIED` or `NO_ONE`, plus an optional `thread_roles` / `reply_roles` allow-list). Prefix colours and levels are editable (`PATCH /api/admin/prefixes/:id`). The staff signature text and banner are the `admin_signature` and `banner_url` settings.


## Going live (checklist)
1. **Database**: create a PostgreSQL database and set `DATABASE_URL` (add `?sslmode=require` for hosted ones). Never run production without it: without `DATABASE_URL` the app uses a temporary in-memory database and everything is lost on restart.
2. **Secrets**: `SESSION_SECRET` (32+ random characters), `PUBLIC_URL` = the exact https address people open (cookies and the CSRF origin check depend on it), `NODE_ENV=production`.
3. **Schema + Owner**: the schema is created automatically on start. To create the Owner without a terminal, set `OWNER_USERNAME`, `OWNER_EMAIL` and `OWNER_PASSWORD` (12+ characters) on the host for the first start, then **delete `OWNER_PASSWORD`** after you log in. (Terminal alternative: `OWNER_PASSWORD='...' npm run create-owner -- YourName you@example.com`.)
4. Log in as Owner, **turn on two-factor** and save the recovery codes, then set the Discord/Instagram/YouTube links, site name, logo and footer text in the admin panel.
5. Optional: `SMTP_URL` (email confirmation and password reset), `GOOGLE_CLIENT_ID`, Turnstile keys.
6. **Backups**: dump the database regularly (`pg_dump`) and keep a copy off the host.
7. Free hosts: see the hosting notes in the chat hand-over (Render + Neon, or an Oracle Cloud Always Free VM). Free tiers change, so check their current terms.
