-- TWINS GAMING forum schema (PostgreSQL 14+). All ids are INT identities.
CREATE TABLE users (
  id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  username TEXT NOT NULL CHECK (username ~ '^[A-Za-z0-9_]{3,24}$'),
  display_name TEXT,
  email TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  is_owner BOOLEAN NOT NULL DEFAULT false,
  email_verified BOOLEAN NOT NULL DEFAULT false,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  banned_until TIMESTAMPTZ, ban_reason TEXT, muted_until TIMESTAMPTZ,
  totp_secret TEXT, totp_enabled BOOLEAN NOT NULL DEFAULT false,
  force_reset BOOLEAN NOT NULL DEFAULT false,
  failed_count INT NOT NULL DEFAULT 0, locked_until TIMESTAMPTZ,
  reg_ip TEXT, last_ip TEXT,
  avatar_url TEXT, banner_url TEXT, bio TEXT, signature TEXT,
  social JSONB NOT NULL DEFAULT '{}', prefs JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), last_login_at TIMESTAMPTZ, last_active_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX users_username_lower ON users (lower(username));
CREATE UNIQUE INDEX users_email_lower ON users (lower(email));
CREATE UNIQUE INDEX users_one_owner ON users (is_owner) WHERE is_owner;       -- exactly one Owner
CREATE INDEX users_reg_ip ON users (reg_ip); CREATE INDEX users_last_ip ON users (last_ip);
CREATE INDEX users_created ON users (created_at); CREATE INDEX users_active ON users (last_active_at);

CREATE TABLE permissions (key TEXT PRIMARY KEY, description TEXT, builtin BOOLEAN NOT NULL DEFAULT true);
CREATE TABLE roles (
  id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, name TEXT NOT NULL, color TEXT NOT NULL DEFAULT '#7c5cff',
  is_staff BOOLEAN NOT NULL DEFAULT false, is_default BOOLEAN NOT NULL DEFAULT false, sort INT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX roles_name_lower ON roles (lower(name));
CREATE TABLE role_permissions (role_id INT NOT NULL REFERENCES roles(id) ON DELETE CASCADE, perm_key TEXT NOT NULL REFERENCES permissions(key) ON DELETE CASCADE ON UPDATE CASCADE, PRIMARY KEY (role_id, perm_key));
CREATE TABLE user_roles (user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE, role_id INT NOT NULL REFERENCES roles(id) ON DELETE CASCADE, PRIMARY KEY (user_id, role_id));

CREATE TABLE sessions (
  id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE, csrf TEXT NOT NULL, ip TEXT, ua TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), last_active_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL, revoked_at TIMESTAMPTZ, reauth_at TIMESTAMPTZ
);
CREATE INDEX sessions_user ON sessions (user_id); CREATE INDEX sessions_ip ON sessions (ip);
CREATE TABLE email_tokens (
  id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose TEXT NOT NULL CHECK (purpose IN ('verify','reset')), token_hash TEXT NOT NULL UNIQUE,
  expires_at TIMESTAMPTZ NOT NULL, used_at TIMESTAMPTZ
);
CREATE TABLE login_attempts (
  id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, username TEXT, ip TEXT, success BOOLEAN NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX login_attempts_ip ON login_attempts (ip, created_at); CREATE INDEX login_attempts_user ON login_attempts (lower(username), created_at);
CREATE TABLE security_logs (
  id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, user_id INT REFERENCES users(id) ON DELETE SET NULL,
  event TEXT NOT NULL, ip TEXT, ua TEXT, meta JSONB NOT NULL DEFAULT '{}', created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX security_event ON security_logs (event, created_at); CREATE INDEX security_ip ON security_logs (ip); CREATE INDEX security_user ON security_logs (user_id, created_at);
CREATE TABLE audit_logs (
  id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, actor_id INT REFERENCES users(id) ON DELETE SET NULL,
  actor_name TEXT, actor_role TEXT, action TEXT NOT NULL, target_type TEXT, target_id TEXT, ip TEXT,
  before JSONB, after JSONB, reason TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX audit_action ON audit_logs (action, created_at); CREATE INDEX audit_actor ON audit_logs (actor_id, created_at); CREATE INDEX audit_target ON audit_logs (target_type, target_id);

CREATE TABLE categories (id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, name TEXT NOT NULL, description TEXT, icon TEXT, banner_url TEXT, sort INT NOT NULL DEFAULT 0, hidden BOOLEAN NOT NULL DEFAULT false, archived BOOLEAN NOT NULL DEFAULT false);
CREATE TABLE prefixes (id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, name TEXT NOT NULL UNIQUE, color TEXT NOT NULL DEFAULT '#ffd000', text_color TEXT NOT NULL DEFAULT '#000000', sort INT NOT NULL DEFAULT 0, advanced BOOLEAN NOT NULL DEFAULT FALSE);
CREATE TABLE forums (
  id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, category_id INT NOT NULL REFERENCES categories(id) ON DELETE CASCADE,
  parent_id INT REFERENCES forums(id) ON DELETE CASCADE, name TEXT NOT NULL, description TEXT, icon TEXT, banner_url TEXT,
  sort INT NOT NULL DEFAULT 0, visibility TEXT NOT NULL DEFAULT 'public' CHECK (visibility IN ('public','members','staff')),
  locked BOOLEAN NOT NULL DEFAULT false, hidden BOOLEAN NOT NULL DEFAULT false, archived BOOLEAN NOT NULL DEFAULT false,
  allow_attachments BOOLEAN NOT NULL DEFAULT true, require_moderation BOOLEAN NOT NULL DEFAULT false,
  allowed_prefixes JSONB, thread_perm TEXT NOT NULL DEFAULT 'CREATE_THREAD', reply_perm TEXT NOT NULL DEFAULT 'REPLY'
);
CREATE INDEX forums_cat ON forums (category_id, sort); CREATE INDEX forums_parent ON forums (parent_id);
CREATE TABLE threads (
  id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, forum_id INT NOT NULL REFERENCES forums(id) ON DELETE CASCADE,
  author_id INT NOT NULL REFERENCES users(id), title TEXT NOT NULL CHECK (char_length(title) BETWEEN 3 AND 200),
  prefix_id INT REFERENCES prefixes(id) ON DELETE SET NULL,
  pinned BOOLEAN NOT NULL DEFAULT false, locked BOOLEAN NOT NULL DEFAULT false, solved BOOLEAN NOT NULL DEFAULT false,
  archived BOOLEAN NOT NULL DEFAULT false, featured BOOLEAN NOT NULL DEFAULT false, approved BOOLEAN NOT NULL DEFAULT true,
  deleted_at TIMESTAMPTZ, views INT NOT NULL DEFAULT 0, reply_count INT NOT NULL DEFAULT 0,
  last_post_at TIMESTAMPTZ NOT NULL DEFAULT now(), last_post_id INT, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX threads_forum ON threads (forum_id, pinned DESC, last_post_at DESC); CREATE INDEX threads_author ON threads (author_id);
CREATE INDEX threads_latest ON threads (last_post_at DESC); CREATE INDEX threads_fts ON threads USING GIN (to_tsvector('simple', title));
CREATE TABLE posts (
  id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, thread_id INT NOT NULL REFERENCES threads(id) ON DELETE CASCADE,
  author_id INT NOT NULL REFERENCES users(id), body TEXT NOT NULL CHECK (char_length(body) BETWEEN 1 AND 20000),
  hidden BOOLEAN NOT NULL DEFAULT false, deleted_at TIMESTAMPTZ, deleted_by INT REFERENCES users(id),
  edited_at TIMESTAMPTZ, edited_by INT REFERENCES users(id), quote_post_id INT REFERENCES posts(id) ON DELETE SET NULL,
  ip TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX posts_thread ON posts (thread_id, id); CREATE INDEX posts_author ON posts (author_id, created_at);
CREATE INDEX posts_fts ON posts USING GIN (to_tsvector('simple', body));
CREATE TABLE post_revisions (id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, post_id INT NOT NULL REFERENCES posts(id) ON DELETE CASCADE, editor_id INT REFERENCES users(id), body TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE reactions (post_id INT NOT NULL REFERENCES posts(id) ON DELETE CASCADE, user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE, type TEXT NOT NULL DEFAULT 'like', created_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY (post_id, user_id));
CREATE TABLE bookmarks (user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE, thread_id INT NOT NULL REFERENCES threads(id) ON DELETE CASCADE, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY (user_id, thread_id));
CREATE TABLE thread_followers (user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE, thread_id INT NOT NULL REFERENCES threads(id) ON DELETE CASCADE, PRIMARY KEY (user_id, thread_id));
CREATE TABLE notifications (id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE, type TEXT NOT NULL, data JSONB NOT NULL DEFAULT '{}', read_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE INDEX notifications_user ON notifications (user_id, read_at, id DESC);

CREATE TABLE conversations (id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, title TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE conversation_users (conversation_id INT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE, user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE, last_read_message_id INT NOT NULL DEFAULT 0, PRIMARY KEY (conversation_id, user_id));
CREATE TABLE media (
  id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, owner_id INT REFERENCES users(id) ON DELETE SET NULL, filename TEXT NOT NULL UNIQUE,
  original_name TEXT, title TEXT, alt TEXT, category TEXT NOT NULL DEFAULT 'Other', mime TEXT NOT NULL, size INT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE messages (id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, conversation_id INT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE, sender_id INT NOT NULL REFERENCES users(id), body TEXT NOT NULL CHECK (char_length(body) BETWEEN 1 AND 10000), media_id INT REFERENCES media(id) ON DELETE SET NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE INDEX messages_conv ON messages (conversation_id, id);
CREATE TABLE blocks (user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE, blocked_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY (user_id, blocked_id));
CREATE TABLE follows (user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE, followed_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY (user_id, followed_id));
CREATE TABLE profile_posts (id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, profile_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE, author_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE, body TEXT NOT NULL CHECK (char_length(body) BETWEEN 1 AND 2000), created_at TIMESTAMPTZ NOT NULL DEFAULT now());

CREATE TABLE statuses (id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, scope TEXT NOT NULL CHECK (scope IN ('report','appeal','application','ticket')), name TEXT NOT NULL, color TEXT NOT NULL DEFAULT '#ffd000', sort INT NOT NULL DEFAULT 0, is_closed BOOLEAN NOT NULL DEFAULT false, UNIQUE (scope, name));
CREATE TABLE history (id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, entity TEXT NOT NULL, entity_id INT NOT NULL, action TEXT NOT NULL, from_value TEXT, to_value TEXT, actor_id INT REFERENCES users(id) ON DELETE SET NULL, note TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE INDEX history_entity ON history (entity, entity_id);
CREATE TABLE notes (id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, entity TEXT NOT NULL, entity_id INT NOT NULL, author_id INT REFERENCES users(id) ON DELETE SET NULL, body TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE INDEX notes_entity ON notes (entity, entity_id);
CREATE TABLE sanctions (
  id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  type TEXT NOT NULL CHECK (type IN ('warn','timeout','ban','unban')), reason TEXT NOT NULL, evidence TEXT,
  staff_id INT REFERENCES users(id) ON DELETE SET NULL, duration_minutes INT, expires_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), modified_at TIMESTAMPTZ
);
CREATE INDEX sanctions_user ON sanctions (user_id, created_at DESC); CREATE INDEX sanctions_type ON sanctions (type, expires_at);
CREATE TABLE reports (
  id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, reporter_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_type TEXT NOT NULL CHECK (target_type IN ('post','thread','user','message','profile','other')), target_id INT,
  category TEXT NOT NULL, details TEXT, status_id INT NOT NULL REFERENCES statuses(id), assignee_id INT REFERENCES users(id) ON DELETE SET NULL,
  resolution TEXT, priority TEXT NOT NULL DEFAULT 'normal', created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX reports_status ON reports (status_id, created_at);
CREATE TABLE appeal_questions (id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, question TEXT NOT NULL, required BOOLEAN NOT NULL DEFAULT true, sort INT NOT NULL DEFAULT 0, active BOOLEAN NOT NULL DEFAULT true);
CREATE TABLE appeals (id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE, sanction_id INT REFERENCES sanctions(id) ON DELETE SET NULL, status_id INT NOT NULL REFERENCES statuses(id), assignee_id INT REFERENCES users(id) ON DELETE SET NULL, answers JSONB NOT NULL DEFAULT '[]', created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE INDEX appeals_status ON appeals (status_id, created_at);
CREATE TABLE application_types (id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, name TEXT NOT NULL, description TEXT, open BOOLEAN NOT NULL DEFAULT false, sort INT NOT NULL DEFAULT 0);
CREATE TABLE application_fields (id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, type_id INT NOT NULL REFERENCES application_types(id) ON DELETE CASCADE, label TEXT NOT NULL, kind TEXT NOT NULL CHECK (kind IN ('text','long','number','dropdown','choice','checkbox','date','file','url')), options JSONB NOT NULL DEFAULT '[]', required BOOLEAN NOT NULL DEFAULT false, sort INT NOT NULL DEFAULT 0);
CREATE TABLE applications (id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, type_id INT NOT NULL REFERENCES application_types(id) ON DELETE CASCADE, user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE, status_id INT NOT NULL REFERENCES statuses(id), assignee_id INT REFERENCES users(id) ON DELETE SET NULL, answers JSONB NOT NULL DEFAULT '{}', created_at TIMESTAMPTZ NOT NULL DEFAULT now(), submitted_at TIMESTAMPTZ, updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE INDEX applications_status ON applications (status_id, created_at);
CREATE TABLE ticket_categories (id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, name TEXT NOT NULL UNIQUE, sort INT NOT NULL DEFAULT 0);
CREATE TABLE tickets (id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE, category_id INT REFERENCES ticket_categories(id) ON DELETE SET NULL, subject TEXT NOT NULL, priority TEXT NOT NULL DEFAULT 'Normal', status_id INT NOT NULL REFERENCES statuses(id), assignee_id INT REFERENCES users(id) ON DELETE SET NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE INDEX tickets_status ON tickets (status_id, updated_at);
CREATE TABLE ticket_messages (id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, ticket_id INT NOT NULL REFERENCES tickets(id) ON DELETE CASCADE, author_id INT REFERENCES users(id) ON DELETE SET NULL, body TEXT NOT NULL, is_staff BOOLEAN NOT NULL DEFAULT false, media_id INT REFERENCES media(id) ON DELETE SET NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());

CREATE TABLE badges (id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT, icon_url TEXT, color TEXT NOT NULL DEFAULT '#ffd000', points INT NOT NULL DEFAULT 0, auto_rule JSONB, sort INT NOT NULL DEFAULT 0);
CREATE TABLE user_badges (user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE, badge_id INT NOT NULL REFERENCES badges(id) ON DELETE CASCADE, awarded_at TIMESTAMPTZ NOT NULL DEFAULT now(), awarded_by INT REFERENCES users(id) ON DELETE SET NULL, PRIMARY KEY (user_id, badge_id));
CREATE TABLE announcements (id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL, image_url TEXT, banner_url TEXT, category TEXT, author_id INT REFERENCES users(id) ON DELETE SET NULL, publish_at TIMESTAMPTZ NOT NULL DEFAULT now(), expires_at TIMESTAMPTZ, pinned BOOLEAN NOT NULL DEFAULT false, featured BOOLEAN NOT NULL DEFAULT false, visibility TEXT NOT NULL DEFAULT 'public' CHECK (visibility IN ('public','members','staff')), notified BOOLEAN NOT NULL DEFAULT false, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE INDEX announcements_pub ON announcements (publish_at);
CREATE TABLE rule_sections (id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, name TEXT NOT NULL, sort INT NOT NULL DEFAULT 0);
CREATE TABLE rules (id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, section_id INT NOT NULL REFERENCES rule_sections(id) ON DELETE CASCADE, title TEXT NOT NULL, body TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','published','archived')), sort INT NOT NULL DEFAULT 0, updated_by INT REFERENCES users(id) ON DELETE SET NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE rule_revisions (id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, rule_id INT NOT NULL REFERENCES rules(id) ON DELETE CASCADE, title TEXT, body TEXT, editor_id INT REFERENCES users(id) ON DELETE SET NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE revision_viewers (user_id INT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, granted_by INT REFERENCES users(id) ON DELETE SET NULL, granted_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE pages (id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, slug TEXT NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9-]{1,60}$'), title TEXT NOT NULL, body TEXT NOT NULL DEFAULT '', image_url TEXT, seo_title TEXT, seo_description TEXT, visibility TEXT NOT NULL DEFAULT 'public' CHECK (visibility IN ('public','members','staff')), nav_placement TEXT, published BOOLEAN NOT NULL DEFAULT false, updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE links (id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL, icon TEXT, location TEXT NOT NULL CHECK (location IN ('header','homepage','forum','sidebar','footer','profile','announcements','custom')), new_tab BOOLEAN NOT NULL DEFAULT true, visible BOOLEAN NOT NULL DEFAULT true, sort INT NOT NULL DEFAULT 0);
CREATE TABLE nav_items (id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, menu TEXT NOT NULL CHECK (menu IN ('header','footer','mobile')), parent_id INT REFERENCES nav_items(id) ON DELETE CASCADE, label TEXT NOT NULL, url TEXT NOT NULL, icon TEXT, visible BOOLEAN NOT NULL DEFAULT true, sort INT NOT NULL DEFAULT 0);
CREATE TABLE settings (key TEXT PRIMARY KEY, value JSONB NOT NULL, updated_by INT REFERENCES users(id) ON DELETE SET NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE content_texts (key TEXT PRIMARY KEY, label TEXT, grp TEXT, value TEXT NOT NULL);
CREATE TABLE email_templates (key TEXT PRIMARY KEY, subject TEXT NOT NULL, body_html TEXT NOT NULL, body_text TEXT NOT NULL, enabled BOOLEAN NOT NULL DEFAULT true);
CREATE TABLE outbox (id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, to_email TEXT NOT NULL, template TEXT, subject TEXT, body_html TEXT, status TEXT NOT NULL DEFAULT 'logged', error TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE backups (id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, kind TEXT NOT NULL, filename TEXT, size INT, status TEXT NOT NULL, error TEXT, created_by INT REFERENCES users(id) ON DELETE SET NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE page_views (day DATE NOT NULL, path TEXT NOT NULL, views INT NOT NULL DEFAULT 0, PRIMARY KEY (day, path));
CREATE TABLE visitors (day DATE NOT NULL, hash TEXT NOT NULL, device TEXT, browser TEXT, referrer TEXT, PRIMARY KEY (day, hash));
