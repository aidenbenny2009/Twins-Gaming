# What works where

| Feature | Open index.html alone (browser-only) | Needs the backend |
|---|---|---|
| Layout, header/nav, forum rows, sidebar, themes, mobile | Works | – |
| Forums/categories edit, nest, drag, copy links, prefixes, permissions UI | Works (saved in this browser only) | Saved for everyone, enforced server-side |
| Post threads/replies, edit, 3-dots menu, hover card, read-dim, follow/ignore | Works (this browser only) | Shared between all visitors, permission checked on server |
| Accounts, passwords, sessions | Demo only (no passwords) | Real scrypt passwords, DB sessions, CSRF |
| 2FA (TOTP) for admins | Not enforced | Enforced |
| Email confirmation, password reset, Google login | Not possible | Needs SMTP + Google client ID |
| Rules, announcements, links, settings, maintenance, roles | Works locally | Saved server-wide (wired) |
| Warnings, bans, audit log, rate limits, security headers | Local simulation | Real |
| Online/Guests counts | Own browser only (guests = 0) | Shared presence |
| Still browser-only even with backend | Navigation editor, brand text, application types, ticket/report/appeal statuses, media library | |
| Warnings (staff only) | Local simulation | Real: needs WARN_USER permission, expires after 1 week, auto-sends a "Warning" conversation to the member |
