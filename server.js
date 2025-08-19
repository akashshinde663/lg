import 'dotenv/config';
import express from 'express';
import crypto from 'crypto';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import mongoose from 'mongoose';
import geoip from 'geoip-lite';

// ====== ENV ======
const {
  PORT = 3000,
  MONGODB_URI,
  IP_HASH_SALT = 'change-me',
  ADMIN_TOKEN,
  STORE_RAW_IP = 'true',      // set to "true" to store raw IP when consent=true
  STORE_PRIVATE_IP = 'true'   // set to "true" to allow storing private/LAN IPs
} = process.env;

if (!MONGODB_URI) {
  console.error('❌ MONGODB_URI is not set.');
  process.exit(1);
}
if (!ADMIN_TOKEN) {
  console.error('❌ ADMIN_TOKEN is not set.');
  process.exit(1);
}

// ====== DB ======
await mongoose.connect(MONGODB_URI);
console.log('✅ Connected to MongoDB');

const ClickSchema = new mongoose.Schema(
  {
    ts: { type: Date, default: Date.now },
    page: String,
    action: { type: String, default: 'click' },

    // IP fields
    raw_ip: String,         // stored only if consent=true and STORE_RAW_IP=true
    is_private: Boolean,    // whether the raw IP is private/LAN/loopback
    ip_anonymized: String,  // IPv4 last octet zeroed / IPv6 coarse zeroing
    ip_hash: String,        // sha256(raw_ip + salt)

    // Coarse geo (public IPs only; private IPs usually resolve to null)
    geo: {
      country: String,
      region: String,
      city: String,
      ll: { type: [Number], default: undefined } // [lat, lon]
    },

    userAgent: String
  },
  { timestamps: true }
);
ClickSchema.index({ createdAt: -1 });
const Click = mongoose.model('Click', ClickSchema);

// ====== APP ======
const app = express();
app.set('trust proxy', true);            // read X-Forwarded-For behind proxies (Render etc.)
app.use(express.json());
app.use(cors());
app.use(helmet());
app.use(morgan('combined'));

// ====== Helpers ======
function normalizeIp(ip) {
  if (!ip) return '';
  // If IPv4 is represented as IPv6, e.g. ::ffff:203.0.113.42
  if (ip.startsWith('::ffff:')) return ip.slice(7);
  return ip;
}
function getClientIp(req) {
  const xff = (req.headers['x-forwarded-for'] || '').toString();
  const first = (xff.split(',')[0] || req.ip || '').trim();
  return normalizeIp(first);
}
function isPrivateIp(ip) {
  if (!ip) return false;
  // IPv4 private/loopback/link-local
  if (/^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.|169\.254\.)/.test(ip)) return true;
  // IPv6 loopback & private/link-local ranges
  if (ip === '::1') return true;
  if (/^fc/i.test(ip) || /^fd/i.test(ip)) return true;   // Unique local
  if (/^fe80:/i.test(ip)) return true;                   // Link-local
  return false;
}
function anonymizeIp(ip) {
  if (!ip) return null;
  if (ip.includes(':')) {
    // IPv6: keep first 3 hextets, zero the rest (coarse)
    const parts = ip.split(':');
    return parts.map((p, i) => (i < 3 ? p : '0')).join(':');
  } else {
    // IPv4: zero last octet
    const parts = ip.split('.');
    if (parts.length === 4) return `${parts[0]}.${parts[1]}.${parts[2]}.0`;
    return ip;
  }
}
function hashIp(ip) {
  if (!ip) return null;
  return crypto.createHmac('sha256', IP_HASH_SALT).update(ip).digest('hex');
}

// ====== Routes ======
app.get('/', (_req, res) => {
  res.type('text').send(
    'Logger is running.\n' +
    'Use /click?consent=true&action=test&page=/ or POST /click.\n' +
    'View logs: /admin/logs?token=YOUR_ADMIN_TOKEN'
  );
});

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, db: mongoose.connection.readyState === 1 ? 'connected' : 'not-connected' });
});

/**
 * One-click logging (GET or POST)
 * Requires: consent=true
 * Optional: action, page
 * Stores raw_ip (including private/LAN) when:
 *  - consent=true
 *  - STORE_RAW_IP=true
 *  - if is_private && STORE_PRIVATE_IP=true (else redacts)
 */
app.all('/click', async (req, res) => {
  try {
    const payload = req.method === 'GET' ? req.query : (req.body || {});
    const { action, page } = payload;
    const consent = String(payload.consent || '').toLowerCase() === 'true';
    if (!consent) {
      return res.status(400).json({ ok: false, error: 'Consent not provided (consent=true required).' });
    }

    const clientIp = getClientIp(req);
    const privateIp = isPrivateIp(clientIp);

    const allowRaw = STORE_RAW_IP.toLowerCase() === 'true';
    const allowPrivate = STORE_PRIVATE_IP.toLowerCase() === 'true';

    // Decide what to store
    const raw_ip =
      allowRaw && (!privateIp || (privateIp && allowPrivate)) ? clientIp : null;

    const ip_anonymized = anonymizeIp(clientIp); // anonymized always saved
    const ip_hash = hashIp(clientIp);            // hashed always saved

    // Coarse geolocation only for public IPs (private usually maps to null)
    let geo = null;
    if (!privateIp && clientIp) {
      const g = geoip.lookup(clientIp);
      if (g) {
        geo = {
          country: g.country || null,
          region: Array.isArray(g.region) ? g.region[0] : g.region || null,
          city: g.city || null,
          ll: Array.isArray(g.ll) ? g.ll : undefined
        };
      }
    }

    const record = {
      ts: new Date(),
      page: page || null,
      action: action || 'click',
      raw_ip,
      is_private: privateIp,
      ip_anonymized,
      ip_hash,
      geo,
      userAgent: req.headers['user-agent'] || null
    };

    const saved = await Click.create(record);

    console.log('Click recorded:', {
      ts: saved.ts,
      action: saved.action,
      raw_ip: saved.raw_ip,
      is_private: saved.is_private,
      geo: saved.geo
    });

    return res.json({ ok: true, stored: saved });
  } catch (err) {
    console.error('Error recording click:', err);
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
});

/**
 * Read last 100 logs (simple admin)
 * Auth via ?token= or Authorization: Bearer <token>
 */
app.get('/admin/logs', async (req, res) => {
  try {
    const token =
      req.query.token ||
      (req.headers.authorization || '').split(' ')[1] ||
      '';
    if (token !== ADMIN_TOKEN) {
      return res.status(401).json({ ok: false, error: 'Unauthorized' });
    }

    const rows = await Click.find().sort({ createdAt: -1 }).limit(100).lean();
    res.json({ ok: true, count: rows.length, rows });
  } catch (err) {
    console.error('Error reading logs:', err);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// Start
app.listen(PORT, () => {
  console.log(`🚀 Logger running on port ${PORT}`);
});
