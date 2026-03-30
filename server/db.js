const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

// DB dans DATA_DIR ou à côté du server.js
const DATA_DIR = process.env.DATA_DIR || __dirname;
const dbPath = path.join(DATA_DIR, 'vox.db');
const envPath = path.join(__dirname, '.env');

// ── AUTO-GENERATE SECRETS ────────────────────────────────────
function ensureSecrets() {
  let envContent = '';
  if (fs.existsSync(envPath)) envContent = fs.readFileSync(envPath, 'utf8');

  const lines = envContent.split('\n').filter(l => l.trim());
  const env = {};
  lines.forEach(line => {
    const [k, ...v] = line.split('=');
    if (k && !k.startsWith('#')) env[k.trim()] = v.join('=').trim();
  });

  let changed = false;
  if (!env.JWT_SECRET || env.JWT_SECRET.length < 64) {
    env.JWT_SECRET = crypto.randomBytes(64).toString('hex');
    changed = true;
  }
  if (!env.ENCRYPTION_KEY || env.ENCRYPTION_KEY.length !== 64) {
    env.ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');
    changed = true;
  }
  if (!env.PORT) {
    env.PORT = '3002';
    changed = true;
  }

  if (changed) {
    const content = Object.entries(env).map(([k, v]) => `${k}=${v}`).join('\n') + '\n';
    fs.writeFileSync(envPath, content, 'utf8');
    console.log('[db] Secrets auto-generated in .env');
  }

  // Set in process.env
  Object.entries(env).forEach(([k, v]) => { if (!process.env[k]) process.env[k] = v; });
}

ensureSecrets();

// ── DATABASE ─────────────────────────────────────────────────
const db = new Database(dbPath);

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('synchronous = NORMAL');
db.pragma('cache_size = -16000');

// ── SCHÉMA v2 ────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    email         TEXT    UNIQUE COLLATE NOCASE,
    password      TEXT    NOT NULL,
    avatar_color  TEXT    NOT NULL DEFAULT '#7c3aed',
    role          TEXT    NOT NULL DEFAULT 'user',
    token_version INTEGER NOT NULL DEFAULT 0,
    banned_at     TEXT,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    username   TEXT    NOT NULL,
    content    TEXT    NOT NULL,
    reply_to   INTEGER REFERENCES messages(id),
    edited_at  TEXT,
    deleted_at TEXT,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS private_messages (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    from_user_id   INTEGER NOT NULL REFERENCES users(id),
    to_user_id     INTEGER NOT NULL REFERENCES users(id),
    from_username  TEXT    NOT NULL,
    to_username    TEXT    NOT NULL,
    content        TEXT    NOT NULL,
    read_at        TEXT,
    created_at     TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS servers (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT    NOT NULL,
    owner_id       INTEGER NOT NULL REFERENCES users(id),
    owner_username TEXT    NOT NULL,
    icon_color     TEXT    NOT NULL DEFAULT '#7c3aed',
    created_at     TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS channels (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id  INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    name       TEXT    NOT NULL,
    type       TEXT    NOT NULL DEFAULT 'text',
    position   INTEGER NOT NULL DEFAULT 0,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS server_members (
    server_id INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    user_id   INTEGER NOT NULL REFERENCES users(id),
    username  TEXT    NOT NULL,
    joined_at TEXT    NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (server_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS server_messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id  INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    channel_id INTEGER REFERENCES channels(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    username   TEXT    NOT NULL,
    content    TEXT    NOT NULL,
    reply_to   INTEGER REFERENCES server_messages(id),
    edited_at  TEXT,
    deleted_at TEXT,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS server_invites (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id  INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    code       TEXT    NOT NULL UNIQUE,
    created_by INTEGER NOT NULL REFERENCES users(id),
    used_by    INTEGER REFERENCES users(id),
    used_at    TEXT,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_messages_created   ON messages(created_at);
  CREATE INDEX IF NOT EXISTS idx_messages_user      ON messages(user_id);
  CREATE INDEX IF NOT EXISTS idx_pm_participants    ON private_messages(from_user_id, to_user_id);
  CREATE INDEX IF NOT EXISTS idx_pm_created         ON private_messages(created_at);
  CREATE INDEX IF NOT EXISTS idx_pm_to_user         ON private_messages(to_user_id);
  CREATE INDEX IF NOT EXISTS idx_channels_server    ON channels(server_id, position);
  CREATE INDEX IF NOT EXISTS idx_smem_user          ON server_members(user_id);

  -- v3: Attachments (files encrypted at rest)
  CREATE TABLE IF NOT EXISTS attachments (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id   INTEGER,
    message_type TEXT    NOT NULL DEFAULT 'global',
    filename     TEXT    NOT NULL,
    mime_type    TEXT    NOT NULL,
    size         INTEGER NOT NULL,
    data         BLOB    NOT NULL,
    created_at   TEXT    NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_attach_msg ON attachments(message_id, message_type);

  -- v3: Reactions
  CREATE TABLE IF NOT EXISTS reactions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id   INTEGER NOT NULL,
    message_type TEXT    NOT NULL DEFAULT 'global',
    server_id    INTEGER,
    channel_id   INTEGER,
    user_id      INTEGER NOT NULL REFERENCES users(id),
    username     TEXT    NOT NULL,
    emoji        TEXT    NOT NULL,
    created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(message_id, message_type, user_id, emoji)
  );
  CREATE INDEX IF NOT EXISTS idx_reactions_msg ON reactions(message_id, message_type);

  -- v3: Mentions
  CREATE TABLE IF NOT EXISTS mentions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id   INTEGER NOT NULL,
    message_type TEXT    NOT NULL DEFAULT 'global',
    server_id    INTEGER,
    channel_id   INTEGER,
    user_id      INTEGER NOT NULL REFERENCES users(id),
    read_at      TEXT,
    created_at   TEXT    NOT NULL DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_mentions_user ON mentions(user_id, read_at);

  -- v3: Read positions for unread badges
  CREATE TABLE IF NOT EXISTS read_positions (
    user_id      INTEGER NOT NULL REFERENCES users(id),
    context      TEXT    NOT NULL,
    last_read_id INTEGER NOT NULL DEFAULT 0,
    updated_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (user_id, context)
  );
`);

// ── MIGRATIONS from v1 ──────────────────────────────────────
const userCols = db.prepare('PRAGMA table_info(users)').all().map(c => c.name);
if (!userCols.includes('email')) {
  db.exec(`ALTER TABLE users ADD COLUMN email TEXT COLLATE NOCASE`);
}
if (!userCols.includes('role')) {
  db.exec(`ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'`);
  db.prepare(`UPDATE users SET role = 'admin' WHERE id = (SELECT MIN(id) FROM users)`).run();
}
if (!userCols.includes('banned_at')) {
  db.exec(`ALTER TABLE users ADD COLUMN banned_at TEXT`);
}

// Migrate servers: add icon_color if missing
const serverCols = db.prepare('PRAGMA table_info(servers)').all().map(c => c.name);
if (!serverCols.includes('icon_color')) {
  db.exec(`ALTER TABLE servers ADD COLUMN icon_color TEXT NOT NULL DEFAULT '#7c3aed'`);
}
// Auto-approve all pending servers (v1 had approval system)
if (serverCols.includes('approved_at')) {
  db.prepare("UPDATE servers SET approved_at = datetime('now') WHERE approved_at IS NULL").run();
}

// Migrate server_messages: add channel_id if missing as nullable
const smCols = db.prepare('PRAGMA table_info(server_messages)').all().map(c => c.name);
if (!smCols.includes('channel_id')) {
  db.exec(`ALTER TABLE server_messages ADD COLUMN channel_id INTEGER REFERENCES channels(id) ON DELETE CASCADE`);
}
db.exec(`CREATE INDEX IF NOT EXISTS idx_smsg_channel ON server_messages(channel_id, created_at)`);

// Migrate private_messages: add read_at if missing
const pmCols = db.prepare('PRAGMA table_info(private_messages)').all().map(c => c.name);
if (!pmCols.includes('read_at')) {
  db.exec(`ALTER TABLE private_messages ADD COLUMN read_at TEXT`);
}

// Ensure every server has at least a #general text channel and a voice channel
const allServers = db.prepare('SELECT id FROM servers').all();
for (const { id } of allServers) {
  const textCh = db.prepare("SELECT id FROM channels WHERE server_id = ? AND type = 'text'").get(id);
  if (!textCh) db.prepare('INSERT INTO channels (server_id, name, type, position) VALUES (?, ?, ?, ?)').run(id, 'general', 'text', 0);
  const voiceCh = db.prepare("SELECT id FROM channels WHERE server_id = ? AND type = 'voice'").get(id);
  if (!voiceCh) db.prepare('INSERT INTO channels (server_id, name, type, position) VALUES (?, ?, ?, ?)').run(id, 'General', 'voice', 100);
  // Assign orphan messages to #general
  const genCh = db.prepare("SELECT id FROM channels WHERE server_id = ? AND type = 'text' ORDER BY position LIMIT 1").get(id);
  if (genCh) db.prepare('UPDATE server_messages SET channel_id = ? WHERE server_id = ? AND channel_id IS NULL').run(genCh.id, id);
}

// ── HELPER: create server with default channels ──────────────
db.createServer = function(name, ownerId, ownerUsername) {
  const colors = ['#7c3aed','#2563eb','#059669','#dc2626','#d97706','#db2777','#0891b2','#65a30d'];
  const iconColor = colors[Math.floor(Math.random() * colors.length)];

  const { lastInsertRowid: serverId } = db.prepare(
    'INSERT INTO servers (name, owner_id, owner_username, icon_color) VALUES (?, ?, ?, ?)'
  ).run(name, ownerId, ownerUsername, iconColor);

  db.prepare('INSERT INTO server_members (server_id, user_id, username) VALUES (?, ?, ?)').run(serverId, ownerId, ownerUsername);
  db.prepare('INSERT INTO channels (server_id, name, type, position) VALUES (?, ?, ?, ?)').run(serverId, 'general', 'text', 0);
  db.prepare('INSERT INTO channels (server_id, name, type, position) VALUES (?, ?, ?, ?)').run(serverId, 'random', 'text', 1);
  db.prepare('INSERT INTO channels (server_id, name, type, position) VALUES (?, ?, ?, ?)').run(serverId, 'General', 'voice', 100);

  return Number(serverId);
};

// ── BACKUP ───────────────────────────────────────────────────
const BACKUP_DIR = path.join(DATA_DIR, 'backups');
db.backup = function() {
  if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const dest = path.join(BACKUP_DIR, `vox-${stamp}.db`);
  db.exec(`VACUUM INTO '${dest.replace(/'/g, "''")}'`);
  const files = fs.readdirSync(BACKUP_DIR).filter(f => f.endsWith('.db')).sort().reverse();
  files.slice(10).forEach(f => fs.unlinkSync(path.join(BACKUP_DIR, f)));
  return dest;
};

module.exports = db;
