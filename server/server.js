// ── ENV ───────────────────────────────────────────────────────
const fs = require('fs');
const envPath = require('path').join(__dirname, '.env');
if (fs.existsSync(envPath)) {
  fs.readFileSync(envPath, 'utf8').split('\n').forEach(line => {
    const [k, ...v] = line.trim().split('=');
    if (k && !k.startsWith('#') && !process.env[k]) process.env[k] = v.join('=');
  });
}

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 64) {
  console.error('[FATAL] JWT_SECRET manquant ou trop court (64 chars min).');
  process.exit(1);
}

const { encrypt, decrypt, encryptBuffer, decryptBuffer } = require('./crypto');
const multer = require('multer');

const express      = require('express');
const http         = require('http');
const { Server }   = require('socket.io');
const cookieParser = require('cookie-parser');
const jwt          = require('jsonwebtoken');
const helmet       = require('helmet');
const rateLimit    = require('express-rate-limit');
const path         = require('path');
const os           = require('os');
const db           = require('./db');
const authRoutes   = require('./routes/auth');

const https  = require('https');
const app    = express();

// HTTPS if certs exist, else HTTP
const certDir = path.join(__dirname, 'certs');
let server;
if (fs.existsSync(path.join(certDir, 'key.pem')) && fs.existsSync(path.join(certDir, 'cert.pem'))) {
  server = https.createServer({
    key:  fs.readFileSync(path.join(certDir, 'key.pem')),
    cert: fs.readFileSync(path.join(certDir, 'cert.pem')),
  }, app);
} else {
  server = http.createServer(app);
}

// ── LAN DETECTION ────────────────────────────────────────────
function getLanIP() {
  const nets = os.networkInterfaces();
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (net.family === 'IPv4' && !net.internal) return net.address;
    }
  }
  return '127.0.0.1';
}

function isPrivateOrigin(origin) {
  if (!origin) return true; // same-origin (Electron, direct)
  try {
    const host = new URL(origin).hostname;
    return host === 'localhost' ||
      host.startsWith('127.') ||
      host.startsWith('192.168.') ||
      host.startsWith('10.') ||
      host.startsWith('100.') || // Tailscale CGNAT range
      /^172\.(1[6-9]|2\d|3[01])\./.test(host) ||
      host === '::1' ||
      host === 'capacitor://localhost' ||
      origin.startsWith('capacitor://');
  } catch { return false; }
}

const io = new Server(server, {
  cors: {
    origin: (origin, cb) => cb(null, isPrivateOrigin(origin)),
    credentials: true,
  },
});

const PORT = process.env.PORT || 3002;
const PUBLIC_URL = process.env.PUBLIC_URL || '';

// Trust Tailscale Funnel / reverse proxy
app.set('trust proxy', 1);

// ── MIDDLEWARE ────────────────────────────────────────────────
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if ((isPrivateOrigin(origin) || (PUBLIC_URL && origin === PUBLIC_URL)) && origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

const isHTTPS = fs.existsSync(path.join(certDir, 'key.pem')) && fs.existsSync(path.join(certDir, 'cert.pem'));
app.use(helmet({
  hsts: { maxAge: 15552000, includeSubDomains: false },
  contentSecurityPolicy: {
    directives: {
      defaultSrc:              ["'self'"],
      scriptSrc:               ["'self'", "'unsafe-inline'"],
      scriptSrcAttr:           ["'unsafe-inline'"],
      styleSrc:                ["'self'", "'unsafe-inline'"],
      connectSrc:              ["'self'", 'ws:', 'wss:'],
      imgSrc:                  ["'self'", 'data:', 'blob:'],
      upgradeInsecureRequests: null, // disable — LAN HTTP, no HTTPS
    },
  },
  crossOriginEmbedderPolicy: false,
}));

app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// Multer for file uploads (10MB max, memory storage)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    // Whitelist stricte : images, audio, vidéo, PDF, ZIP, texte brut
    const ALLOWED_MIME = new Set([
      'image/jpeg', 'image/png', 'image/gif', 'image/webp',
      'audio/mpeg', 'audio/ogg', 'audio/wav', 'audio/webm',
      'video/mp4', 'video/webm', 'video/ogg',
      'application/pdf', 'application/zip',
      'text/plain',
    ]);
    if (!ALLOWED_MIME.has(file.mimetype)) return cb(new Error('Type non autorisé'));
    cb(null, true);
  },
});

// Rate limiting
app.use(rateLimit({ windowMs: 60_000, max: 300, standardHeaders: true, legacyHeaders: false }));
const authLimiter = rateLimit({ windowMs: 15 * 60_000, max: 10, message: { error: 'Trop de tentatives.' } });
app.use('/auth', authLimiter, authRoutes);

// ── AUTH MIDDLEWARE ───────────────────────────────────────────
function requireAuth(req, res, next) {
  const token = req.cookies?.token || req.headers.authorization?.replace(/^Bearer\s+/i, '') || null;
  if (!token) return res.status(401).json({ error: 'Non authentifié.' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user    = db.prepare('SELECT token_version, banned_at, role FROM users WHERE id = ?').get(payload.id);
    if (!user || user.token_version !== payload.tv)
      return res.status(401).json({ error: 'Session révoquée.' });
    if (user.banned_at)
      return res.status(403).json({ error: 'Compte banni.' });
    req.user = { ...payload, role: user.role };
    next();
  } catch {
    res.status(401).json({ error: 'Token invalide.' });
  }
}

function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé.' });
    next();
  });
}

// ── ROUTES ───────────────────────────────────────────────────
app.get('/', (_, res) => res.sendFile(path.join(__dirname, 'public', 'app.html')));

// Server info (version seulement — IP LAN réservée à l'admin authentifié)
app.get('/api/info', (req, res) => {
  const token = req.cookies?.token || req.headers.authorization?.replace(/^Bearer\s+/i, '') || null;
  let isAdmin = false;
  if (token) {
    try {
      const payload = jwt.verify(token, JWT_SECRET);
      const user = db.prepare('SELECT role FROM users WHERE id = ?').get(payload.id);
      if (user?.role === 'admin') isAdmin = true;
    } catch {}
  }
  res.json({ version: '3.0.0', name: 'Realm', ...(isAdmin && { lan: getLanIP() }) });
});

// Global messages
app.get('/api/messages', requireAuth, (req, res) => {
  const since = Math.max(0, parseInt(req.query.since) || 0);
  try {
    const rows = db.prepare(`
      SELECT
        m.id, m.username, u.avatar_color,
        CASE WHEN m.deleted_at IS NOT NULL THEN NULL ELSE m.content END AS content,
        m.created_at, m.edited_at,
        (m.deleted_at IS NOT NULL) AS is_deleted,
        m.reply_to,
        CASE WHEN m.deleted_at IS NOT NULL THEN NULL ELSE rm.content END AS reply_content,
        rm.username AS reply_username,
        a.id AS att_id, a.filename AS att_filename, a.mime_type AS att_mime
      FROM messages m
      JOIN users u ON u.id = m.user_id
      LEFT JOIN messages rm ON rm.id = m.reply_to AND rm.deleted_at IS NULL
      LEFT JOIN attachments a ON a.message_id = m.id AND a.message_type = 'global'
      WHERE m.id > ?
      ORDER BY m.created_at ASC LIMIT 100
    `).all(since);
    res.json(rows.map(r => {
      const msg = { ...r, is_deleted: !!r.is_deleted, content: decrypt(r.content), reply_content: decrypt(r.reply_content) };
      if (r.att_id) msg.attachment = { id: r.att_id, filename: r.att_filename, mime_type: r.att_mime };
      delete msg.att_id; delete msg.att_filename; delete msg.att_mime;
      return msg;
    }));
  } catch (e) {
    console.error('[api/messages]', e.message);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// ── PRIVATE MESSAGES (OFFLINE SUPPORT) ───────────────────────

// Unread PM count — doit être avant /api/pm/:username pour éviter le shadowing
app.get('/api/pm/unread', requireAuth, (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT from_username, COUNT(*) as count
      FROM private_messages
      WHERE to_user_id = ? AND read_at IS NULL
      GROUP BY from_username
    `).all(req.user.id);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: 'Erreur serveur.' }); }
});

// PM conversations list — doit être avant /api/pm/:username pour éviter le shadowing
app.get('/api/pm/conversations', requireAuth, (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT
        CASE WHEN pm.from_user_id = ? THEN pm.to_username ELSE pm.from_username END AS partner,
        MAX(pm.created_at) AS last_at,
        SUM(CASE WHEN pm.to_user_id = ? AND pm.read_at IS NULL THEN 1 ELSE 0 END) AS unread
      FROM private_messages pm
      WHERE pm.from_user_id = ? OR pm.to_user_id = ?
      GROUP BY partner
      ORDER BY last_at DESC
    `).all(req.user.id, req.user.id, req.user.id, req.user.id);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: 'Erreur serveur.' }); }
});

// Conversation avec un utilisateur (avec pagination)
app.get('/api/pm/:username', requireAuth, (req, res) => {
  const other = req.params.username;
  if (!other || other.length > 20) return res.status(400).json({ error: 'Paramètre invalide.' });
  const before = parseInt(req.query.before) || 0;
  const limit  = Math.min(parseInt(req.query.limit) || 50, 100);
  try {
    const rows = db.prepare(`
      SELECT pm.id, pm.from_username, pm.to_username, pm.content, pm.created_at, pm.read_at, u.avatar_color,
        a.id AS att_id, a.filename AS att_filename, a.mime_type AS att_mime
      FROM private_messages pm
      JOIN users u ON u.username = pm.from_username COLLATE NOCASE
      LEFT JOIN attachments a ON a.message_id = pm.id AND a.message_type = 'dm'
      WHERE ((pm.from_user_id = ? AND pm.to_username = ? COLLATE NOCASE)
         OR  (pm.to_user_id   = ? AND pm.from_username = ? COLLATE NOCASE))
        AND (? = 0 OR pm.id < ?)
      ORDER BY pm.created_at DESC LIMIT ?
    `).all(req.user.id, other, req.user.id, other, before, before, limit).reverse();

    // Mark received messages as read
    db.prepare(`
      UPDATE private_messages SET read_at = datetime('now')
      WHERE to_user_id = ? AND from_username = ? COLLATE NOCASE AND read_at IS NULL
    `).run(req.user.id, other);

    res.json(rows.map(r => {
      const msg = { ...r, content: decrypt(r.content) };
      if (r.att_id) msg.attachment = { id: r.att_id, filename: r.att_filename, mime_type: r.att_mime };
      delete msg.att_id; delete msg.att_filename; delete msg.att_mime;
      return msg;
    }));
  } catch (e) {
    console.error('[api/pm]', e.message);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// ── SERVER ROUTES (DIRECT CREATE, NO APPROVAL) ──────────────
app.get('/api/servers', requireAuth, (req, res) => {
  try {
    const rows = db.prepare(`
      SELECT s.id, s.name, s.owner_id, s.owner_username, s.icon_color
      FROM servers s
      JOIN server_members sm ON sm.server_id = s.id
      WHERE sm.user_id = ?
      ORDER BY s.created_at ASC
    `).all(req.user.id);
    res.json(rows);
  } catch (e) { res.status(500).json({ error: 'Erreur serveur.' }); }
});

// Direct server creation (no approval needed)
app.post('/api/servers', requireAuth, (req, res) => {
  const { name } = req.body ?? {};
  if (!name?.trim() || name.length > 30)
    return res.status(400).json({ error: 'Nom invalide (30 chars max).' });
  const count = db.prepare('SELECT COUNT(*) as c FROM servers WHERE owner_id = ?').get(req.user.id).c;
  if (count >= 10) return res.status(409).json({ error: 'Maximum 10 serveurs par utilisateur.' });
  try {
    const serverId = db.createServer(name.trim(), req.user.id, req.user.username);
    const srv = db.prepare('SELECT * FROM servers WHERE id = ?').get(serverId);
    const channels = db.prepare('SELECT * FROM channels WHERE server_id = ? ORDER BY position').all(serverId);
    res.json({ ...srv, channels });
  } catch (e) {
    console.error('[create server]', e.message);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// Channels for a server
app.get('/api/servers/:id/channels', requireAuth, (req, res) => {
  const serverId = parseInt(req.params.id);
  if (!serverId) return res.status(400).json({ error: 'ID invalide.' });
  const member = db.prepare('SELECT 1 FROM server_members WHERE server_id = ? AND user_id = ?').get(serverId, req.user.id);
  if (!member && req.user.role !== 'admin') return res.status(403).json({ error: 'Non membre.' });
  try {
    const channels = db.prepare('SELECT * FROM channels WHERE server_id = ? ORDER BY position').all(serverId);
    res.json(channels);
  } catch (e) { res.status(500).json({ error: 'Erreur serveur.' }); }
});

// Create channel
app.post('/api/servers/:id/channels', requireAuth, (req, res) => {
  const serverId = parseInt(req.params.id);
  const { name, type } = req.body ?? {};
  if (!name?.trim() || name.length > 30) return res.status(400).json({ error: 'Nom invalide.' });
  if (!['text', 'voice'].includes(type)) return res.status(400).json({ error: 'Type invalide.' });
  const srv = db.prepare('SELECT owner_id FROM servers WHERE id = ?').get(serverId);
  if (!srv) return res.status(404).json({ error: 'Serveur introuvable.' });
  if (srv.owner_id !== req.user.id && req.user.role !== 'admin')
    return res.status(403).json({ error: 'Seul le propriétaire peut créer des channels.' });
  const count = db.prepare('SELECT COUNT(*) as c FROM channels WHERE server_id = ?').get(serverId).c;
  if (count >= 50) return res.status(409).json({ error: 'Maximum 50 channels.' });
  try {
    const maxPos = db.prepare('SELECT MAX(position) as m FROM channels WHERE server_id = ? AND type = ?').get(serverId, type).m || 0;
    const { lastInsertRowid } = db.prepare('INSERT INTO channels (server_id, name, type, position) VALUES (?, ?, ?, ?)')
      .run(serverId, name.trim().toLowerCase().replace(/\s+/g, '-'), type, maxPos + 1);
    const channel = db.prepare('SELECT * FROM channels WHERE id = ?').get(Number(lastInsertRowid));
    io.to(`server:${serverId}`).emit('channel_created', { serverId, channel });
    res.json(channel);
  } catch (e) { res.status(500).json({ error: 'Erreur serveur.' }); }
});

// Delete channel
app.delete('/api/servers/:id/channels/:channelId', requireAuth, (req, res) => {
  const serverId = parseInt(req.params.id);
  const channelId = parseInt(req.params.channelId);
  const srv = db.prepare('SELECT owner_id FROM servers WHERE id = ?').get(serverId);
  if (!srv) return res.status(404).json({ error: 'Serveur introuvable.' });
  if (srv.owner_id !== req.user.id && req.user.role !== 'admin')
    return res.status(403).json({ error: 'Accès refusé.' });
  // Don't allow deleting the last text channel
  const textCount = db.prepare("SELECT COUNT(*) as c FROM channels WHERE server_id = ? AND type = 'text'").get(serverId).c;
  const ch = db.prepare('SELECT type FROM channels WHERE id = ? AND server_id = ?').get(channelId, serverId);
  if (!ch) return res.status(404).json({ error: 'Channel introuvable.' });
  if (ch.type === 'text' && textCount <= 1) return res.status(400).json({ error: 'Impossible de supprimer le dernier channel texte.' });
  try {
    db.prepare('DELETE FROM channels WHERE id = ? AND server_id = ?').run(channelId, serverId);
    io.to(`server:${serverId}`).emit('channel_deleted', { serverId, channelId });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Erreur serveur.' }); }
});

// Channel messages
app.get('/api/servers/:id/channels/:channelId/messages', requireAuth, (req, res) => {
  const serverId = parseInt(req.params.id);
  const channelId = parseInt(req.params.channelId);
  if (!serverId || !channelId) return res.status(400).json({ error: 'ID invalide.' });
  const member = db.prepare('SELECT 1 FROM server_members WHERE server_id = ? AND user_id = ?').get(serverId, req.user.id);
  if (!member && req.user.role !== 'admin') return res.status(403).json({ error: 'Non membre.' });
  const since = Math.max(0, parseInt(req.query.since) || 0);
  try {
    const rows = db.prepare(`
      SELECT sm.id, sm.username, u.avatar_color,
        CASE WHEN sm.deleted_at IS NOT NULL THEN NULL ELSE sm.content END AS content,
        sm.created_at, sm.edited_at,
        (sm.deleted_at IS NOT NULL) AS is_deleted,
        sm.reply_to,
        CASE WHEN sm.deleted_at IS NOT NULL THEN NULL ELSE rm.content END AS reply_content,
        rm.username AS reply_username,
        a.id AS att_id, a.filename AS att_filename, a.mime_type AS att_mime
      FROM server_messages sm
      JOIN users u ON u.id = sm.user_id
      LEFT JOIN server_messages rm ON rm.id = sm.reply_to AND rm.deleted_at IS NULL
      LEFT JOIN attachments a ON a.message_id = sm.id AND a.message_type = 'server'
      WHERE sm.server_id = ? AND sm.channel_id = ? AND sm.id > ?
      ORDER BY sm.created_at ASC LIMIT 100
    `).all(serverId, channelId, since);
    res.json(rows.map(r => {
      const msg = { ...r, is_deleted: !!r.is_deleted, content: decrypt(r.content), reply_content: decrypt(r.reply_content) };
      if (r.att_id) msg.attachment = { id: r.att_id, filename: r.att_filename, mime_type: r.att_mime };
      delete msg.att_id; delete msg.att_filename; delete msg.att_mime;
      return msg;
    }));
  } catch (e) { res.status(500).json({ error: 'Erreur serveur.' }); }
});

// Server members
app.get('/api/servers/:id/members', requireAuth, (req, res) => {
  const serverId = parseInt(req.params.id);
  const member = db.prepare('SELECT 1 FROM server_members WHERE server_id = ? AND user_id = ?').get(serverId, req.user.id);
  if (!member && req.user.role !== 'admin') return res.status(403).json({ error: 'Non membre.' });
  try {
    const members = db.prepare(`
      SELECT sm.user_id, sm.username, u.avatar_color, u.role
      FROM server_members sm JOIN users u ON u.id = sm.user_id
      WHERE sm.server_id = ?
    `).all(serverId);
    res.json(members);
  } catch (e) { res.status(500).json({ error: 'Erreur serveur.' }); }
});

// Invite
app.post('/api/servers/:id/invite', requireAuth, (req, res) => {
  const serverId = parseInt(req.params.id);
  const srv = db.prepare('SELECT * FROM servers WHERE id = ?').get(serverId);
  if (!srv) return res.status(404).json({ error: 'Serveur introuvable.' });
  if (srv.owner_id !== req.user.id && req.user.role !== 'admin')
    return res.status(403).json({ error: 'Seul le propriétaire peut inviter.' });
  try {
    const code = require('crypto').randomBytes(8).toString('hex').toUpperCase();
    db.prepare('INSERT INTO server_invites (server_id, code, created_by) VALUES (?, ?, ?)').run(serverId, code, req.user.id);
    res.json({ code, server_name: srv.name });
  } catch (e) { res.status(500).json({ error: 'Erreur serveur.' }); }
});

// Join via invite
app.post('/api/servers/join', requireAuth, (req, res) => {
  const { code } = req.body ?? {};
  if (!code?.trim()) return res.status(400).json({ error: 'Code manquant.' });
  try {
    const invite = db.prepare(`
      SELECT si.*, s.name FROM server_invites si
      JOIN servers s ON s.id = si.server_id
      WHERE si.code = ? AND si.used_at IS NULL
        AND datetime(si.created_at, '+7 days') > datetime('now')
    `).get(code.trim().toUpperCase());
    if (!invite) return res.status(404).json({ error: 'Code invalide ou déjà utilisé.' });
    const already = db.prepare('SELECT 1 FROM server_members WHERE server_id = ? AND user_id = ?').get(invite.server_id, req.user.id);
    if (already) return res.status(409).json({ error: 'Tu es déjà membre de ce serveur.' });
    db.prepare('INSERT INTO server_members (server_id, user_id, username) VALUES (?, ?, ?)').run(invite.server_id, req.user.id, req.user.username);
    db.prepare("UPDATE server_invites SET used_by = ?, used_at = datetime('now') WHERE id = ?").run(req.user.id, invite.id);
    res.json({ ok: true, server_id: invite.server_id, server_name: invite.name });
  } catch (e) { res.status(500).json({ error: 'Erreur serveur.' }); }
});

// ── FILE UPLOAD ──────────────────────────────────────────────
const uploadLimiter    = rateLimit({ windowMs: 60 * 60_000, max: 20, message: { error: 'Trop de fichiers.' } });
const mentionsLimiter  = rateLimit({ windowMs: 60_000, max: 30, message: { error: 'Trop de requêtes.' } });
app.post('/api/upload', requireAuth, uploadLimiter, (req, res, next) => {
  upload.single('file')(req, res, (err) => {
    if (err) {
      if (err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'Fichier trop gros (10MB max).' });
      return res.status(400).json({ error: err.message || 'Erreur upload.' });
    }
    if (!req.file) return res.status(400).json({ error: 'Aucun fichier.' });

    try {
      const { type, serverId, channelId, toUsername } = JSON.parse(req.body.context || '{}');
      const file = req.file;
      const encData = encryptBuffer(file.buffer);
      const created_at = new Date().toISOString();
      let messageId, messageType = type || 'global';

      if (messageType === 'server') {
        if (!serverId || !channelId) return res.status(400).json({ error: 'serverId/channelId requis.' });
        const m = db.prepare('SELECT 1 FROM server_members WHERE server_id = ? AND user_id = ?').get(serverId, req.user.id);
        if (!m) return res.status(403).json({ error: 'Non membre.' });
        const marker = `[file:${file.originalname}]`;
        const { lastInsertRowid } = db.prepare(
          'INSERT INTO server_messages (server_id, channel_id, user_id, username, content, created_at) VALUES (?, ?, ?, ?, ?, ?)'
        ).run(serverId, channelId, req.user.id, req.user.username, encrypt(marker), created_at);
        messageId = Number(lastInsertRowid);
      } else if (messageType === 'dm') {
        if (!toUsername) return res.status(400).json({ error: 'toUsername requis.' });
        const toUser = db.prepare('SELECT id FROM users WHERE username = ? COLLATE NOCASE').get(toUsername);
        if (!toUser) return res.status(404).json({ error: 'Utilisateur introuvable.' });
        const marker = `[file:${file.originalname}]`;
        const { lastInsertRowid } = db.prepare(
          'INSERT INTO private_messages (from_user_id, to_user_id, from_username, to_username, content, created_at) VALUES (?, ?, ?, ?, ?, ?)'
        ).run(req.user.id, toUser.id, req.user.username, toUsername, encrypt(marker), created_at);
        messageId = Number(lastInsertRowid);
      } else {
        const marker = `[file:${file.originalname}]`;
        const { lastInsertRowid } = db.prepare(
          'INSERT INTO messages (user_id, username, content, created_at) VALUES (?, ?, ?, ?)'
        ).run(req.user.id, req.user.username, encrypt(marker), created_at);
        messageId = Number(lastInsertRowid);
      }

      // Store encrypted file
      const { lastInsertRowid: attachId } = db.prepare(
        'INSERT INTO attachments (message_id, message_type, filename, mime_type, size, data) VALUES (?, ?, ?, ?, ?, ?)'
      ).run(messageId, messageType, file.originalname, file.mimetype, file.size, encData);

      const attachment = { id: Number(attachId), filename: file.originalname, mime_type: file.mimetype, size: file.size };
      const user = db.prepare('SELECT avatar_color FROM users WHERE id = ?').get(req.user.id);

      // Emit via socket
      if (messageType === 'server') {
        io.to(`server:${serverId}`).emit('server_new_message', {
          serverId, channelId, id: messageId, username: req.user.username,
          avatar_color: user.avatar_color, content: `[file:${file.originalname}]`,
          created_at, attachment,
        });
      } else if (messageType === 'dm') {
        const payload = { id: messageId, from_username: req.user.username, to_username: toUsername,
          content: `[file:${file.originalname}]`, avatar_color: user.avatar_color, created_at, attachment };
        // Send to both users
        for (const [sid, u] of onlineUsers.entries()) {
          if (u.username === req.user.username || u.username.toLowerCase() === toUsername.toLowerCase()) {
            io.to(sid).emit('private_message', payload);
          }
        }
      } else {
        io.emit('new_message', {
          id: messageId, username: req.user.username, avatar_color: user.avatar_color,
          content: `[file:${file.originalname}]`, created_at, attachment,
        });
      }

      res.json({ ok: true, attachment });
    } catch (e) {
      console.error('[upload]', e.message);
      res.status(500).json({ error: 'Erreur serveur.' });
    }
  });
});

// Serve attachment (decrypted)
app.get('/api/attachments/:id', requireAuth, (req, res) => {
  const id = parseInt(req.params.id);
  if (!id) return res.status(400).json({ error: 'ID invalide.' });
  try {
    const att = db.prepare('SELECT * FROM attachments WHERE id = ?').get(id);
    if (!att) return res.status(404).json({ error: 'Fichier introuvable.' });

    // Access check for server messages
    if (att.message_type === 'server') {
      const sm = db.prepare('SELECT server_id FROM server_messages WHERE id = ?').get(att.message_id);
      if (sm) {
        const m = db.prepare('SELECT 1 FROM server_members WHERE server_id = ? AND user_id = ?').get(sm.server_id, req.user.id);
        if (!m && req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé.' });
      }
    }
    // Access check for DMs
    if (att.message_type === 'dm') {
      const pm = db.prepare('SELECT from_user_id, to_user_id FROM private_messages WHERE id = ?').get(att.message_id);
      if (pm && pm.from_user_id !== req.user.id && pm.to_user_id !== req.user.id && req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Accès refusé.' });
      }
    }

    const decrypted = decryptBuffer(att.data);
    if (!decrypted) return res.status(500).json({ error: 'Erreur déchiffrement.' });

    const isImage = att.mime_type.startsWith('image/');
    // Sanitize filename pour éviter l'injection dans Content-Disposition
    const safeFilename = att.filename.replace(/["\r\n\\]/g, '_');
    res.setHeader('Content-Type', att.mime_type);
    res.setHeader('Content-Disposition', `${isImage ? 'inline' : 'attachment'}; filename="${safeFilename}"`);
    res.setHeader('Content-Length', decrypted.length);
    res.setHeader('Cache-Control', 'private, max-age=3600');
    res.send(decrypted);
  } catch (e) {
    console.error('[attachment]', e.message);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// ── SEARCH ──────────────────────────────────────────────────
const searchLimiter = rateLimit({ windowMs: 60_000, max: 10, message: { error: 'Trop de recherches.' } });
app.get('/api/search', requireAuth, searchLimiter, (req, res) => {
  const q = (req.query.q || '').trim();
  const scope = req.query.scope || 'global';
  if (q.length < 2 || q.length > 100) return res.status(400).json({ error: 'Recherche: 2-100 caractères.' });

  try {
    const pattern = `%${q}%`;
    let results = [];

    if (scope === 'global') {
      const rows = db.prepare(`
        SELECT m.id, m.username, u.avatar_color, m.content, m.created_at
        FROM messages m JOIN users u ON u.id = m.user_id
        WHERE m.deleted_at IS NULL
        ORDER BY m.created_at DESC LIMIT 50
      `).all();
      results = rows.map(r => ({ ...r, content: decrypt(r.content) }))
        .filter(r => r.content && r.content.toLowerCase().includes(q.toLowerCase()));
    } else if (scope === 'server') {
      const serverId = parseInt(req.query.serverId);
      const channelId = parseInt(req.query.channelId);
      if (!serverId) return res.status(400).json({ error: 'serverId requis.' });
      const m = db.prepare('SELECT 1 FROM server_members WHERE server_id = ? AND user_id = ?').get(serverId, req.user.id);
      if (!m && req.user.role !== 'admin') return res.status(403).json({ error: 'Non membre.' });
      const params = channelId ? [serverId, channelId] : [serverId];
      const chFilter = channelId ? 'AND sm.channel_id = ?' : '';
      const rows = db.prepare(`
        SELECT sm.id, sm.username, u.avatar_color, sm.content, sm.created_at, sm.channel_id
        FROM server_messages sm JOIN users u ON u.id = sm.user_id
        WHERE sm.server_id = ? ${chFilter} AND sm.deleted_at IS NULL
        ORDER BY sm.created_at DESC LIMIT 100
      `).all(...params);
      results = rows.map(r => ({ ...r, content: decrypt(r.content) }))
        .filter(r => r.content && r.content.toLowerCase().includes(q.toLowerCase()))
        .slice(0, 50);
    } else if (scope === 'dm') {
      const partner = req.query.partner;
      if (!partner) return res.status(400).json({ error: 'partner requis.' });
      const rows = db.prepare(`
        SELECT pm.id, pm.from_username, pm.to_username, pm.content, pm.created_at
        FROM private_messages pm
        WHERE ((pm.from_user_id = ? AND pm.to_username = ? COLLATE NOCASE)
            OR (pm.to_user_id = ? AND pm.from_username = ? COLLATE NOCASE))
        ORDER BY pm.created_at DESC LIMIT 200
      `).all(req.user.id, partner, req.user.id, partner);
      results = rows.map(r => ({ ...r, username: r.from_username, content: decrypt(r.content) }))
        .filter(r => r.content && r.content.toLowerCase().includes(q.toLowerCase()))
        .slice(0, 50);
    }

    res.json(results);
  } catch (e) {
    console.error('[search]', e.message);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// ── READ POSITIONS (unread badges) ──────────────────────────
app.post('/api/read-position', requireAuth, (req, res) => {
  const { context, lastReadId } = req.body ?? {};
  if (!context || typeof context !== 'string' || !Number.isInteger(lastReadId)) {
    return res.status(400).json({ error: 'Paramètres invalides.' });
  }
  try {
    db.prepare(`
      INSERT INTO read_positions (user_id, context, last_read_id, updated_at)
      VALUES (?, ?, ?, datetime('now'))
      ON CONFLICT(user_id, context) DO UPDATE SET last_read_id = MAX(last_read_id, excluded.last_read_id), updated_at = datetime('now')
    `).run(req.user.id, context, lastReadId);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Erreur serveur.' }); }
});

app.get('/api/unread-counts', requireAuth, (req, res) => {
  try {
    const counts = {};
    // Global
    const globalPos = db.prepare('SELECT last_read_id FROM read_positions WHERE user_id = ? AND context = ?').get(req.user.id, 'global');
    const globalLast = globalPos?.last_read_id || 0;
    const globalUnread = db.prepare('SELECT COUNT(*) as c FROM messages WHERE id > ? AND deleted_at IS NULL').get(globalLast);
    if (globalUnread.c > 0) counts['global'] = globalUnread.c;

    // Servers the user is a member of
    const memberships = db.prepare('SELECT server_id FROM server_members WHERE user_id = ?').all(req.user.id);
    for (const { server_id } of memberships) {
      const channels = db.prepare("SELECT id FROM channels WHERE server_id = ? AND type = 'text'").all(server_id);
      for (const { id: chId } of channels) {
        const ctx = `server:${server_id}:${chId}`;
        const pos = db.prepare('SELECT last_read_id FROM read_positions WHERE user_id = ? AND context = ?').get(req.user.id, ctx);
        const last = pos?.last_read_id || 0;
        const unread = db.prepare('SELECT COUNT(*) as c FROM server_messages WHERE channel_id = ? AND id > ? AND deleted_at IS NULL').get(chId, last);
        if (unread.c > 0) counts[ctx] = unread.c;
      }
    }

    res.json(counts);
  } catch (e) {
    console.error('[unread-counts]', e.message);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// ── MENTIONS ────────────────────────────────────────────────
app.get('/api/mentions/unread', requireAuth, (req, res) => {
  try {
    const count = db.prepare('SELECT COUNT(*) as c FROM mentions WHERE user_id = ? AND read_at IS NULL').get(req.user.id);
    res.json({ count: count.c });
  } catch (e) { res.status(500).json({ error: 'Erreur serveur.' }); }
});

app.post('/api/mentions/read', requireAuth, mentionsLimiter, (req, res) => {
  const { context } = req.body ?? {};
  try {
    if (context) {
      // Parse context to filter mentions
      const parts = context.split(':');
      if (parts[0] === 'global') {
        db.prepare("UPDATE mentions SET read_at = datetime('now') WHERE user_id = ? AND message_type = 'global' AND read_at IS NULL").run(req.user.id);
      } else if (parts[0] === 'server' && parts[1] && parts[2]) {
        db.prepare("UPDATE mentions SET read_at = datetime('now') WHERE user_id = ? AND server_id = ? AND channel_id = ? AND read_at IS NULL").run(req.user.id, parts[1], parts[2]);
      }
    } else {
      db.prepare("UPDATE mentions SET read_at = datetime('now') WHERE user_id = ? AND read_at IS NULL").run(req.user.id);
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Erreur serveur.' }); }
});

// ── REACTIONS ─────────────────────────────────────────────────
app.get('/api/reactions', requireAuth, (req, res) => {
  const idsParam = req.query.ids;
  if (!idsParam) return res.json({});
  const ids = idsParam.split(',').map(Number).filter(n => n > 0).slice(0, 200);
  if (ids.length === 0) return res.json({});
  try {
    const placeholders = ids.map(() => '?').join(',');
    const rows = db.prepare(
      `SELECT message_id, emoji, username FROM reactions WHERE message_id IN (${placeholders}) ORDER BY created_at`
    ).all(...ids);
    const result = {};
    for (const r of rows) {
      if (!result[r.message_id]) result[r.message_id] = [];
      result[r.message_id].push({ emoji: r.emoji, username: r.username });
    }
    res.json(result);
  } catch (e) { res.status(500).json({ error: 'Erreur serveur.' }); }
});

// ── ADMIN ROUTES ──────────────────────────────────────────────
app.get('/api/admin/users', requireAdmin, (_, res) => {
  try {
    const users = db.prepare('SELECT id, username, email, role, banned_at, created_at FROM users ORDER BY created_at ASC').all();
    res.json(users);
  } catch (e) { res.status(500).json({ error: 'Erreur serveur.' }); }
});

app.post('/api/admin/ban', requireAdmin, (req, res) => {
  const { username: target, ban } = req.body ?? {};
  if (!target || typeof target !== 'string') return res.status(400).json({ error: 'Paramètre manquant.' });
  if (target.toLowerCase() === req.user.username.toLowerCase())
    return res.status(400).json({ error: 'Impossible de se bannir soi-même.' });
  try {
    db.prepare(
      ban
        ? "UPDATE users SET banned_at = datetime('now') WHERE username = ? COLLATE NOCASE AND role != 'admin'"
        : 'UPDATE users SET banned_at = NULL WHERE username = ? COLLATE NOCASE'
    ).run(target);
    if (ban) {
      const entry = [...onlineUsers.entries()].find(([, u]) => u.username.toLowerCase() === target.toLowerCase());
      if (entry) {
        io.to(entry[0]).emit('kicked', { reason: 'Vous avez été banni par un administrateur.' });
        io.sockets.sockets.get(entry[0])?.disconnect(true);
      }
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Erreur serveur.' }); }
});

app.get('/api/admin/servers', requireAdmin, (_, res) => {
  try {
    const rows = db.prepare(`
      SELECT s.*, COUNT(sm.user_id) as member_count
      FROM servers s LEFT JOIN server_members sm ON sm.server_id = s.id
      GROUP BY s.id ORDER BY s.created_at DESC
    `).all();
    res.json(rows);
  } catch (e) { res.status(500).json({ error: 'Erreur serveur.' }); }
});

app.post('/api/admin/role', requireAdmin, (req, res) => {
  const { username: target, role: newRole } = req.body ?? {};
  if (!target || !['user', 'admin'].includes(newRole))
    return res.status(400).json({ error: 'Paramètre invalide.' });
  if (target.toLowerCase() === req.user.username.toLowerCase())
    return res.status(400).json({ error: 'Impossible de modifier son propre rôle.' });
  try {
    db.prepare('UPDATE users SET role = ? WHERE username = ? COLLATE NOCASE').run(newRole, target);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Erreur serveur.' }); }
});

// Backup endpoint
app.post('/api/admin/backup', requireAdmin, (_, res) => {
  try {
    db.backup();
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Erreur backup.' }); }
});

// ── SOCKET AUTH ───────────────────────────────────────────────
io.use((socket, next) => {
  const token = socket.handshake.auth?.token
    ?? socket.handshake.headers.cookie?.match(/(?:^|;\s*)token=([^;]+)/)?.[1];
  if (!token) return next(new Error('Non authentifié.'));
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user    = db.prepare('SELECT token_version, avatar_color, role, banned_at FROM users WHERE id = ?').get(payload.id);
    if (!user || user.token_version !== payload.tv) return next(new Error('Session révoquée.'));
    if (user.banned_at) return next(new Error('Compte banni.'));
    socket.user = { ...payload, avatar_color: user.avatar_color, role: user.role };
    next();
  } catch {
    next(new Error('Token invalide.'));
  }
});

// ── RATE LIMITERS SOCKET ─────────────────────────────────────
function makeLimiter(max, windowMs) {
  const map = new Map();
  function check(key) {
    const now = Date.now();
    const w   = map.get(key);
    if (!w || now > w.reset) { map.set(key, { count: 1, reset: now + windowMs }); return true; }
    if (w.count >= max) return false;
    w.count++;
    return true;
  }
  check.clear = (k) => map.delete(k);
  setInterval(() => {
    const now = Date.now();
    for (const [k, w] of map) if (now > w.reset) map.delete(k);
  }, 5 * 60_000).unref();
  return check;
}

const rl = {
  msg:    makeLimiter(20, 60_000),
  edit:   makeLimiter(20, 60_000),
  del:    makeLimiter(10, 60_000),
  pm:     makeLimiter(30, 60_000),
  typing: makeLimiter(30, 60_000),
  voice:  makeLimiter(10, 60_000),
  offer:  makeLimiter(10, 60_000),
  answer: makeLimiter(10, 60_000),
  ice:      makeLimiter(200, 60_000),
  reaction: makeLimiter(30, 60_000),
  readpos:  makeLimiter(60, 60_000),
};

// ── STATE ─────────────────────────────────────────────────────
const onlineUsers      = new Map(); // socketId → { id, username, avatar_color, role }
const voiceUsers       = new Map(); // username → { username, avatar_color, muted, deafened }
const serverVoiceUsers = new Map(); // channelId → Map<username, {username, avatar_color}>
const cooldowns        = new Map();

function isInt(v) { return Number.isInteger(v) && v > 0; }

function uniqueUsers() {
  const seen = new Set();
  const out  = [];
  for (const u of onlineUsers.values()) {
    if (!seen.has(u.id)) { seen.add(u.id); out.push(u); }
  }
  return out;
}

// ── SOCKET EVENTS ─────────────────────────────────────────────
io.on('connection', (socket) => {
  const { id: userId, username, avatar_color, role } = socket.user;
  onlineUsers.set(socket.id, { id: userId, username, avatar_color, role });
  io.emit('online_users', uniqueUsers());
  console.log(`+ ${username}`);

  // ── GLOBAL MESSAGES ──
  socket.on('send_message', (data) => {
    const content = typeof data === 'string' ? data : data?.content;
    const replyTo = (typeof data === 'object' && isInt(data?.replyTo)) ? data.replyTo : null;
    if (!content?.trim() || content.length > 2000) return;
    if (!rl.msg(socket.id)) return;
    const now = Date.now();
    if (now - (cooldowns.get(socket.id) || 0) < 400) return;
    cooldowns.set(socket.id, now);

    const clean = content.trim();
    try {
      const created_at = new Date().toISOString();
      const { lastInsertRowid: msgId } = db.prepare(
        'INSERT INTO messages (user_id, username, content, reply_to, created_at) VALUES (?, ?, ?, ?, ?)'
      ).run(userId, username, encrypt(clean), replyTo, created_at);

      let reply_content = null, reply_username = null;
      if (replyTo) {
        const rm = db.prepare('SELECT content, username FROM messages WHERE id = ? AND deleted_at IS NULL').get(replyTo);
        if (rm) { reply_content = decrypt(rm.content); reply_username = rm.username; }
      }

      const msgPayload = {
        id: msgId, username, avatar_color, content: clean,
        created_at, reply_to: replyTo, reply_content, reply_username,
      };

      // Parse @mentions
      const mentionRegex = /@(\w{1,20})\b/g;
      let match;
      while ((match = mentionRegex.exec(clean)) !== null) {
        const mentioned = db.prepare('SELECT id FROM users WHERE username = ? COLLATE NOCASE').get(match[1]);
        if (mentioned && mentioned.id !== userId) {
          db.prepare('INSERT OR IGNORE INTO mentions (message_id, message_type, user_id) VALUES (?, ?, ?)').run(msgId, 'global', mentioned.id);
          // Notify online mentioned user
          for (const [sid, u] of onlineUsers.entries()) {
            if (u.id === mentioned.id) {
              io.to(sid).emit('mention_notification', { messageId: msgId, from: username, content: clean.slice(0, 100), context: 'global' });
            }
          }
        }
      }

      io.emit('new_message', msgPayload);
    } catch (e) { console.error('[send_message]', e.message); }
  });

  socket.on('edit_message', ({ id, content }) => {
    if (!isInt(id) || !content?.trim() || content.length > 2000) return;
    if (!rl.edit(socket.id)) return;
    const clean = content.trim();
    try {
      const edited_at = new Date().toISOString();
      const r = db.prepare(
        'UPDATE messages SET content = ?, edited_at = ? WHERE id = ? AND user_id = ? AND deleted_at IS NULL'
      ).run(encrypt(clean), edited_at, id, userId);
      if (r.changes) io.emit('message_edited', { id, content: clean, edited_at });
    } catch (e) { console.error('[edit_message]', e.message); }
  });

  socket.on('delete_message', ({ id }) => {
    if (!isInt(id)) return;
    if (!rl.del(socket.id)) return;
    try {
      const isAdmin = role === 'admin';
      const stmt = isAdmin
        ? "UPDATE messages SET deleted_at = datetime('now') WHERE id = ? AND deleted_at IS NULL"
        : "UPDATE messages SET deleted_at = datetime('now') WHERE id = ? AND user_id = ? AND deleted_at IS NULL";
      const r = db.prepare(stmt).run(...(isAdmin ? [id] : [id, userId]));
      if (r.changes) io.emit('message_deleted', { id });
    } catch (e) { console.error('[delete_message]', e.message); }
  });

  // ── PRIVATE MESSAGES (OFFLINE SUPPORT) ──
  socket.on('private_message', ({ to, content }) => {
    if (!to || typeof to !== 'string' || to.length > 20) return;
    if (!content?.trim() || content.length > 2000) return;
    if (!rl.pm(socket.id)) return;

    const toClean = to.trim();
    if (toClean.toLowerCase() === username.toLowerCase()) return;
    const clean = content.trim();

    try {
      const toUser = db.prepare('SELECT id FROM users WHERE username = ? COLLATE NOCASE').get(toClean);
      if (!toUser) {
        socket.emit('pm_error', { error: `Utilisateur "${toClean}" introuvable.` });
        return;
      }

      const created_at = new Date().toISOString();
      const { lastInsertRowid: pmId } = db.prepare(
        'INSERT INTO private_messages (from_user_id, to_user_id, from_username, to_username, content, created_at) VALUES (?, ?, ?, ?, ?, ?)'
      ).run(userId, toUser.id, username, toClean, encrypt(clean), created_at);

      const payload = { id: Number(pmId), from_username: username, to_username: toClean, content: clean, avatar_color, created_at };

      // Send to sender
      socket.emit('private_message', payload);

      // Send to recipient if online
      const recipientEntry = [...onlineUsers.entries()].find(
        ([, u]) => u.username.toLowerCase() === toClean.toLowerCase()
      );
      if (recipientEntry) {
        io.to(recipientEntry[0]).emit('private_message', payload);
      }
    } catch (e) { console.error('[private_message]', e.message); }
  });

  // ── TYPING ──
  socket.on('typing',      () => { if (rl.typing(socket.id)) socket.broadcast.emit('user_typing', username); });
  socket.on('stop_typing', () => socket.broadcast.emit('user_stop_typing', username));

  // ── GLOBAL VOICE ──
  socket.on('join_voice', () => {
    if (!rl.voice(socket.id)) return;
    voiceUsers.set(username, { username, avatar_color });
    socket.join('voice');
    io.emit('voice_users', [...voiceUsers.values()]);
    socket.to('voice').emit('voice_peer_joined', { socketId: socket.id, username });
  });

  socket.on('leave_voice', () => {
    voiceUsers.delete(username);
    socket.leave('voice');
    io.emit('voice_users', [...voiceUsers.values()]);
    socket.to('voice').emit('voice_peer_left', { socketId: socket.id });
  });

  // WebRTC signaling (global)
  socket.on('webrtc_offer',  ({ to, offer })     => {
    if (typeof to !== 'string' || !onlineUsers.has(to) || !rl.offer(socket.id)) return;
    io.to(to).emit('webrtc_offer', { from: socket.id, username, offer });
  });
  socket.on('webrtc_answer', ({ to, answer })    => {
    if (typeof to !== 'string' || !onlineUsers.has(to) || !rl.answer(socket.id)) return;
    io.to(to).emit('webrtc_answer', { from: socket.id, answer });
  });
  socket.on('webrtc_ice',    ({ to, candidate }) => {
    if (typeof to !== 'string' || !onlineUsers.has(to) || !rl.ice(socket.id)) return;
    io.to(to).emit('webrtc_ice', { from: socket.id, candidate });
  });

  // ── SERVER ROOMS ──
  socket.on('join_server_room', ({ serverId }) => {
    if (!Number.isInteger(serverId)) return;
    const m = db.prepare('SELECT 1 FROM server_members WHERE server_id = ? AND user_id = ?').get(serverId, userId);
    if (!m && role !== 'admin') return;
    socket.join(`server:${serverId}`);
  });
  socket.on('leave_server_room', ({ serverId }) => {
    if (Number.isInteger(serverId)) socket.leave(`server:${serverId}`);
  });

  // ── SERVER MESSAGES (CHANNEL-BASED) ──
  socket.on('server_message', ({ serverId, channelId, content, replyTo }) => {
    if (!isInt(serverId) || !isInt(channelId) || !content?.trim() || content.length > 2000) return;
    if (!rl.msg(socket.id)) return;
    const m = db.prepare('SELECT 1 FROM server_members WHERE server_id = ? AND user_id = ?').get(serverId, userId);
    if (!m) return;
    // Verify channel belongs to server
    const ch = db.prepare('SELECT id FROM channels WHERE id = ? AND server_id = ?').get(channelId, serverId);
    if (!ch) return;
    const clean = content.trim();
    const created_at = new Date().toISOString();
    const rTo = isInt(replyTo) ? replyTo : null;
    try {
      const { lastInsertRowid: msgId } = db.prepare(
        'INSERT INTO server_messages (server_id, channel_id, user_id, username, content, reply_to, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
      ).run(serverId, channelId, userId, username, encrypt(clean), rTo, created_at);
      let reply_content = null, reply_username = null;
      if (rTo) {
        const rm = db.prepare('SELECT content, username FROM server_messages WHERE id = ? AND deleted_at IS NULL').get(rTo);
        if (rm) { reply_content = decrypt(rm.content); reply_username = rm.username; }
      }
      const srvMsgPayload = {
        serverId, channelId, id: msgId, username, avatar_color, content: clean,
        created_at, reply_to: rTo, reply_content, reply_username,
      };

      // Parse @mentions
      const mentionRegex2 = /@(\w{1,20})\b/g;
      let smMatch;
      while ((smMatch = mentionRegex2.exec(clean)) !== null) {
        const mentioned = db.prepare('SELECT id FROM users WHERE username = ? COLLATE NOCASE').get(smMatch[1]);
        if (mentioned && mentioned.id !== userId) {
          const isMember = db.prepare('SELECT 1 FROM server_members WHERE server_id = ? AND user_id = ?').get(serverId, mentioned.id);
          if (isMember) {
            db.prepare('INSERT OR IGNORE INTO mentions (message_id, message_type, server_id, channel_id, user_id) VALUES (?, ?, ?, ?, ?)').run(msgId, 'server', serverId, channelId, mentioned.id);
            for (const [sid, u] of onlineUsers.entries()) {
              if (u.id === mentioned.id) {
                io.to(sid).emit('mention_notification', { messageId: msgId, from: username, content: clean.slice(0, 100), context: `server:${serverId}:${channelId}` });
              }
            }
          }
        }
      }

      io.to(`server:${serverId}`).emit('server_new_message', srvMsgPayload);
    } catch (e) { console.error('[server_message]', e.message); }
  });

  socket.on('server_edit_message', ({ serverId, id, content }) => {
    if (!isInt(serverId) || !isInt(id) || !content?.trim() || content.length > 2000) return;
    if (!rl.edit(socket.id)) return;
    try {
      const edited_at = new Date().toISOString();
      const clean = content.trim();
      const r = db.prepare(
        'UPDATE server_messages SET content = ?, edited_at = ? WHERE id = ? AND server_id = ? AND user_id = ? AND deleted_at IS NULL'
      ).run(encrypt(clean), edited_at, id, serverId, userId);
      if (r.changes) io.to(`server:${serverId}`).emit('server_message_edited', { serverId, id, content: clean, edited_at });
    } catch (e) { console.error('[server_edit_message]', e.message); }
  });

  socket.on('server_delete_message', ({ serverId, id }) => {
    if (!isInt(serverId) || !isInt(id)) return;
    if (!rl.del(socket.id)) return;
    try {
      const isAdmin = role === 'admin';
      const stmt = isAdmin
        ? "UPDATE server_messages SET deleted_at = datetime('now') WHERE id = ? AND server_id = ? AND deleted_at IS NULL"
        : "UPDATE server_messages SET deleted_at = datetime('now') WHERE id = ? AND server_id = ? AND user_id = ? AND deleted_at IS NULL";
      const r = db.prepare(stmt).run(...(isAdmin ? [id, serverId] : [id, serverId, userId]));
      if (r.changes) io.to(`server:${serverId}`).emit('server_message_deleted', { serverId, id });
    } catch (e) { console.error('[server_delete_message]', e.message); }
  });

  // ── SERVER VOICE (PER CHANNEL) ──
  socket.on('server_join_voice', ({ serverId, channelId }) => {
    if (!isInt(serverId) || !isInt(channelId) || !rl.voice(socket.id)) return;
    const m = db.prepare('SELECT 1 FROM server_members WHERE server_id = ? AND user_id = ?').get(serverId, userId);
    if (!m) return;
    const ch = db.prepare("SELECT id FROM channels WHERE id = ? AND server_id = ? AND type = 'voice'").get(channelId, serverId);
    if (!ch) return;
    socket.join(`voice:${channelId}`);
    if (!serverVoiceUsers.has(channelId)) serverVoiceUsers.set(channelId, new Map());
    serverVoiceUsers.get(channelId).set(username, { username, avatar_color });
    io.to(`server:${serverId}`).emit('server_voice_users', { serverId, channelId, users: [...serverVoiceUsers.get(channelId).values()] });
    socket.to(`voice:${channelId}`).emit('server_voice_peer_joined', { serverId, channelId, socketId: socket.id, username });
  });

  socket.on('server_leave_voice', ({ serverId, channelId }) => {
    if (!isInt(channelId)) return;
    socket.leave(`voice:${channelId}`);
    serverVoiceUsers.get(channelId)?.delete(username);
    const users = [...(serverVoiceUsers.get(channelId)?.values() || [])];
    if (isInt(serverId)) {
      io.to(`server:${serverId}`).emit('server_voice_users', { serverId, channelId, users });
    }
    socket.to(`voice:${channelId}`).emit('server_voice_peer_left', { serverId, channelId, socketId: socket.id });
  });

  // Server WebRTC signaling
  socket.on('server_webrtc_offer',  ({ serverId, to, offer })     => {
    if (!isInt(serverId) || typeof to !== 'string' || !onlineUsers.has(to) || !rl.offer(socket.id)) return;
    io.to(to).emit('server_webrtc_offer', { serverId, from: socket.id, username, offer });
  });
  socket.on('server_webrtc_answer', ({ serverId, to, answer })    => {
    if (!isInt(serverId) || typeof to !== 'string' || !onlineUsers.has(to) || !rl.answer(socket.id)) return;
    io.to(to).emit('server_webrtc_answer', { serverId, from: socket.id, answer });
  });
  socket.on('server_webrtc_ice',    ({ serverId, to, candidate }) => {
    if (!isInt(serverId) || typeof to !== 'string' || !onlineUsers.has(to) || !rl.ice(socket.id)) return;
    io.to(to).emit('server_webrtc_ice', { serverId, from: socket.id, candidate });
  });

  // ── REACTIONS ──
  socket.on('toggle_reaction', ({ messageId, emoji, messageType, serverId, channelId }) => {
    if (!isInt(messageId) || !emoji || typeof emoji !== 'string') return;
    // Accepter uniquement les vrais emojis (pas de guillemets ou code injectables)
    if (!/^[\p{Emoji_Presentation}\p{Extended_Pictographic}][\p{Emoji_Modifier}\uFE0F\u20E3]?[\u200D\p{Emoji_Presentation}\p{Extended_Pictographic}\uFE0F]*$/u.test(emoji)) return;
    if (!rl.reaction(socket.id)) return;
    messageType = messageType || 'global';
    if (!['global', 'server', 'dm'].includes(messageType)) return;

    try {
      const existing = db.prepare(
        'SELECT id FROM reactions WHERE message_id = ? AND message_type = ? AND user_id = ? AND emoji = ?'
      ).get(messageId, messageType, userId, emoji);

      if (existing) {
        db.prepare('DELETE FROM reactions WHERE id = ?').run(existing.id);
      } else {
        db.prepare(
          'INSERT INTO reactions (message_id, message_type, server_id, channel_id, user_id, username, emoji) VALUES (?, ?, ?, ?, ?, ?, ?)'
        ).run(messageId, messageType, serverId || null, channelId || null, userId, username, emoji);
      }

      // Aggregate reactions for this message
      const reactions = db.prepare(
        'SELECT emoji, GROUP_CONCAT(username) as users, COUNT(*) as count FROM reactions WHERE message_id = ? AND message_type = ? GROUP BY emoji'
      ).all(messageId, messageType).map(r => ({ emoji: r.emoji, count: r.count, users: r.users.split(',') }));

      const payload = { messageId, messageType, reactions };
      if (messageType === 'server' && serverId) {
        io.to(`server:${serverId}`).emit('reaction_updated', payload);
      } else {
        io.emit('reaction_updated', payload);
      }
    } catch (e) { console.error('[toggle_reaction]', e.message); }
  });

  // ── VOICE MUTE/DEAFEN ──
  socket.on('voice_mute_state', ({ muted }) => {
    const vu = voiceUsers.get(username);
    if (vu) { vu.muted = !!muted; io.emit('voice_users', [...voiceUsers.values()]); }
    // Server voice
    for (const [chId, chVoice] of serverVoiceUsers) {
      const svu = chVoice.get(username);
      if (svu) {
        svu.muted = !!muted;
        const ch = db.prepare('SELECT server_id FROM channels WHERE id = ?').get(chId);
        if (ch) io.to(`server:${ch.server_id}`).emit('server_voice_users', { serverId: ch.server_id, channelId: chId, users: [...chVoice.values()] });
      }
    }
  });

  socket.on('voice_deafen_state', ({ deafened }) => {
    const vu = voiceUsers.get(username);
    if (vu) { vu.deafened = !!deafened; io.emit('voice_users', [...voiceUsers.values()]); }
    for (const [chId, chVoice] of serverVoiceUsers) {
      const svu = chVoice.get(username);
      if (svu) {
        svu.deafened = !!deafened;
        const ch = db.prepare('SELECT server_id FROM channels WHERE id = ?').get(chId);
        if (ch) io.to(`server:${ch.server_id}`).emit('server_voice_users', { serverId: ch.server_id, channelId: chId, users: [...chVoice.values()] });
      }
    }
  });

  // ── READ POSITION (via socket for real-time) ──
  socket.on('update_read_position', ({ context, lastReadId }) => {
    if (!context || typeof context !== 'string' || !Number.isInteger(lastReadId)) return;
    if (!rl.readpos(socket.id)) return;
    try {
      db.prepare(`
        INSERT INTO read_positions (user_id, context, last_read_id, updated_at)
        VALUES (?, ?, ?, datetime('now'))
        ON CONFLICT(user_id, context) DO UPDATE SET last_read_id = MAX(last_read_id, excluded.last_read_id), updated_at = datetime('now')
      `).run(userId, context, lastReadId);
    } catch (e) { console.error('[read_position]', e.message); }
  });

  // ── ADMIN SOCKET ──
  socket.on('kick_user', ({ username: target }) => {
    if (role !== 'admin' || typeof target !== 'string') return;
    const entry = [...onlineUsers.entries()].find(([, u]) => u.username.toLowerCase() === target.toLowerCase());
    if (entry) {
      io.to(entry[0]).emit('kicked', { reason: `Vous avez été expulsé par ${username}.` });
      io.sockets.sockets.get(entry[0])?.disconnect(true);
    }
  });

  // ── DISCONNECT ──
  socket.on('disconnect', () => {
    onlineUsers.delete(socket.id);
    voiceUsers.delete(username);
    cooldowns.delete(socket.id);
    Object.values(rl).forEach(l => l.clear(socket.id));
    io.emit('online_users', uniqueUsers());
    io.emit('voice_users', [...voiceUsers.values()]);
    socket.to('voice').emit('voice_peer_left', { socketId: socket.id });
    // Clean server voice channels
    for (const [chId, chVoice] of serverVoiceUsers) {
      if (chVoice.has(username)) {
        chVoice.delete(username);
        const users = [...chVoice.values()];
        // Find serverId from channel
        const ch = db.prepare('SELECT server_id FROM channels WHERE id = ?').get(chId);
        if (ch) {
          io.to(`server:${ch.server_id}`).emit('server_voice_users', { serverId: ch.server_id, channelId: chId, users });
          socket.to(`voice:${chId}`).emit('server_voice_peer_left', { serverId: ch.server_id, channelId: chId, socketId: socket.id });
        }
      }
    }
    console.log(`- ${username}`);
  });
});

// ── GLOBAL ERROR HANDLER (ne pas exposer les stack traces) ───
app.use((err, req, res, next) => {
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Payload trop volumineux.' });
  }
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'JSON invalide.' });
  }
  console.error('[server error]', err.message);
  res.status(500).json({ error: 'Erreur serveur.' });
});

// ── AUTO BACKUP (every 6 hours) ──────────────────────────────
setInterval(() => {
  try { db.backup(); console.log('[backup] Auto-backup OK'); }
  catch (e) { console.error('[backup]', e.message); }
}, 6 * 60 * 60_000).unref();

// ── START ─────────────────────────────────────────────────────
const HOST = '0.0.0.0';
server.listen(PORT, HOST, () => {
  const lanIP = getLanIP();
  const proto = server instanceof https.Server ? 'https' : 'http';
  console.log(`Realm v3.0 — ${proto}://localhost:${PORT}`);
  console.log(`LAN: ${proto}://${lanIP}:${PORT}`);
});

module.exports = { app, server, io };
