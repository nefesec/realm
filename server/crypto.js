// ── AES-256-GCM encryption helper ────────────────────────────
// Format stocké : "enc:<iv_hex>:<authTag_hex>:<ciphertext_hex>"
// Les anciennes valeurs en clair (sans préfixe "enc:") sont retournées telles quelles.

const crypto = require('crypto');

const KEY = (() => {
  const hex = process.env.ENCRYPTION_KEY;
  if (!hex || hex.length !== 64 || !/^[0-9a-fA-F]{64}$/.test(hex)) {
    console.error('[FATAL] ENCRYPTION_KEY manquante ou invalide (64 chars hex = 32 bytes requis).');
    process.exit(1);
  }
  return Buffer.from(hex, 'hex');
})();

function encrypt(text) {
  if (text == null) return null;
  const iv     = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const enc    = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  const tag    = cipher.getAuthTag();
  return `enc:${iv.toString('hex')}:${tag.toString('hex')}:${enc.toString('hex')}`;
}

function decrypt(str) {
  if (str == null) return null;
  if (!str.startsWith('enc:')) return str; // rétrocompat données en clair
  const parts = str.split(':');
  if (parts.length !== 4) return str;
  const [, ivHex, tagHex, dataHex] = parts;
  try {
    const iv       = Buffer.from(ivHex, 'hex');
    const tag      = Buffer.from(tagHex, 'hex');
    const data     = Buffer.from(dataHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
    decipher.setAuthTag(tag);
    return decipher.update(data).toString('utf8') + decipher.final('utf8');
  } catch {
    return null; // données corrompues
  }
}

// ── Binary encryption for file uploads ──
function encryptBuffer(buf) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const enc = Buffer.concat([cipher.update(buf), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]); // 16 + 16 + data
}

function decryptBuffer(buf) {
  if (!buf || buf.length < 33) return null;
  const iv = buf.subarray(0, 16);
  const tag = buf.subarray(16, 32);
  const data = buf.subarray(32);
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(data), decipher.final()]);
  } catch {
    return null;
  }
}

module.exports = { encrypt, decrypt, encryptBuffer, decryptBuffer };
