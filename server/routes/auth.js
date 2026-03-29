const express = require('express');
const argon2  = require('argon2');
const jwt     = require('jsonwebtoken');
const db      = require('../db');

const router = express.Router();

const ARGON_OPTS = {
  type:        argon2.argon2id,
  memoryCost:  65536,
  timeCost:    3,
  parallelism: 1,
};

const COLORS = [
  '#7c3aed','#2563eb','#059669','#dc2626',
  '#d97706','#db2777','#0891b2','#65a30d',
];

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

function cookieOpts(req) {
  return {
    httpOnly: true,
    sameSite: 'lax',
    secure:   req ? req.secure : false, // true si HTTPS actif
    maxAge:   7 * 24 * 60 * 60 * 1000,
  };
}

// ── INSCRIPTION ──────────────────────────────────────────────
router.post('/register', async (req, res) => {
  const { username, email, password } = req.body ?? {};

  if (!username || !password)
    return res.status(400).json({ error: 'Pseudo et mot de passe requis.' });
  if (username.length < 2 || username.length > 20)
    return res.status(400).json({ error: 'Pseudo : 2 à 20 caractères.' });
  if (!/^[a-zA-Z0-9_-]+$/.test(username))
    return res.status(400).json({ error: 'Pseudo : lettres, chiffres, - et _ uniquement.' });
  if (email && !EMAIL_RE.test(email))
    return res.status(400).json({ error: 'Email invalide.' });
  if (password.length < 8 || password.length > 128)
    return res.status(400).json({ error: 'Mot de passe : 8 à 128 caractères.' });

  try {
    const hash  = await argon2.hash(password, ARGON_OPTS);
    const color = COLORS[Math.floor(Math.random() * COLORS.length)];
    const stmt  = db.prepare('INSERT INTO users (username, email, password, avatar_color) VALUES (?, ?, ?, ?)');
    const { lastInsertRowid: id } = stmt.run(username, email ? email.toLowerCase() : null, hash, color);
    // Premier inscrit = admin
    const userCount = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
    if (userCount === 1) db.prepare("UPDATE users SET role = 'admin' WHERE id = ?").run(id);

    const token = jwt.sign({ id, username, tv: 0 }, process.env.JWT_SECRET, { expiresIn: '7d' });
    const isMobile = !req.cookies?.token && !!req.headers.origin?.startsWith('capacitor');
    res.cookie('token', token, cookieOpts(req)).json({ ok: true, username, ...(isMobile && { token }) });
  } catch (e) {
    if (e.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      // Distinguer pseudo vs email
      const byEmail = db.prepare('SELECT id FROM users WHERE email = ? COLLATE NOCASE').get(email);
      if (byEmail) return res.status(409).json({ error: 'Email déjà utilisé.' });
      return res.status(409).json({ error: 'Pseudo déjà pris.' });
    }
    console.error('[register]', e.message);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// ── CONNEXION ────────────────────────────────────────────────
router.post('/login', async (req, res) => {
  const { username, password } = req.body ?? {};
  if (!username || !password)
    return res.status(400).json({ error: 'Champs manquants.' });
  if (password.length > 128)
    return res.status(400).json({ error: 'Mot de passe trop long.' });

  try {
    // Accepte pseudo ou email
    const user = db.prepare(
      'SELECT * FROM users WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE'
    ).get(username, username);

    const dummy = '$argon2id$v=19$m=65536,t=3,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    const ok = user
      ? await argon2.verify(user.password, password)
      : await argon2.verify(dummy, password).catch(() => false);

    if (!user || !ok || user.banned_at)
      return res.status(401).json({ error: 'Identifiants invalides.' });

    const token = jwt.sign(
      { id: user.id, username: user.username, tv: user.token_version },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    const isMobile = !req.cookies?.token && !!req.headers.origin?.startsWith('capacitor');
    res.cookie('token', token, cookieOpts(req)).json({ ok: true, username: user.username, ...(isMobile && { token }) });
  } catch (e) {
    console.error('[login]', e.message);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// ── DÉCONNEXION ──────────────────────────────────────────────
router.post('/logout', (req, res) => {
  res.clearCookie('token').json({ ok: true });
});

// ── SESSION ──────────────────────────────────────────────────
router.get('/me', (req, res) => {
  const token = req.cookies?.token || req.headers.authorization?.replace(/^Bearer\s+/i, '') || null;
  if (!token) return res.status(401).json({ error: 'Non authentifié.' });
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const user = db.prepare('SELECT id, username, avatar_color, token_version, role, banned_at FROM users WHERE id = ?').get(payload.id);
    if (!user || user.token_version !== payload.tv)
      return res.status(401).json({ error: 'Session révoquée.' });
    if (user.banned_at)
      return res.status(403).json({ error: 'Compte banni.' });
    res.json({ id: user.id, username: user.username, avatar_color: user.avatar_color, role: user.role });
  } catch {
    res.status(401).json({ error: 'Token invalide.' });
  }
});

module.exports = router;
