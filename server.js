import 'dotenv/config';
import express from 'express';
import mongoose from 'mongoose';
import helmet from 'helmet';
import morgan from 'morgan';
import cors from 'cors';
import fetch from 'node-fetch';
import geoip from 'geoip-lite';

// ====== ENV ======
const {
  PORT = 3000,
  MONGODB_URI,
  ADMIN_TOKEN,
  GEO_PROVIDER = 'ipapi', // 'ipapi' or 'geoip'
  REDIRECT_AFTER = '',    // e.g., 'https://example.com' (optional)
} = process.env;

if (!MONGODB_URI) {
  console.error('❌ MONGODB_URI not set');
  process.exit(1);
}
if (!ADMIN_TOKEN) {
  console.error('❌ ADMIN_TOKEN not set');
  process.exit(1);
}

// ====== DB ======
await mongoose.connect(MONGODB_URI);
console.log('✅ Connected to MongoDB');

const ClickSchema = new mongoose.Schema({
  ts: { type: Date, default: Date.now },
  raw_ip: String,
  is_private: Boolean,
  ua: String,
  // Geo fields
  country: String,
  region: String,
  city: String,
  postal: String,       // pincode / zip when available
  lat: Number,
  lon: Number,
  source: String,       // 'ipapi' or 'geoip-lite'
  // Optional: request context
  path: String,
  ref: String,
}, { timestamps: true });
ClickSchema.index({ createdAt: -1 });
const Click = mongoose.model('Click', ClickSchema);

// ====== APP ======
const app = express();
app.set('trust proxy', true);  // required on Render/behind proxies
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(morgan('combined'));

// ====== Helpers ======
function normalizeIp(ip) {
  if (!ip) return '';
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
  if (/^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.|169\.254\.)/.test(ip)) return true;
  if (ip === '::1') return true;
  if (/^fc/i.test(ip) || /^fd/i.test(ip)) return true;   // IPv6 ULA
  if (/^fe80:/i.test(ip)) return true;                   // IPv6 link-local
  return false;
}
function pixel1x1(res) {
  const buf = Buffer.from(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAokB9l0oM3kAAAAASUVORK5CYII=',
    'base64'
  );
  res.set('Content-Type', 'image/png');
  res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.send(buf);
}

// External geo (postal, lat/lon, better accuracy on public IPs)
async function lookupIpapi(ip) {
  // ipapi.co has a free, no-key JSON endpoint with rate limits.
  // Replace with a paid provider + key if you need reliability.
  const url = `https://ipapi.co/${encodeURIComponent(ip)}/json/`;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 3500);
  try {
    const r = await fetch(url, { signal: ctrl.signal });
    if (!r.ok) throw new Error(`ipapi status ${r.status}`);
    const j = await r.json();
    return {
      ok: true,
      country: j.country || null,
      region: j.region || j.region_code || null,
      city: j.city || null,
      postal: j.postal || null,
      lat: typeof j.latitude === 'number' ? j.latitude : (j.latitude ? Number(j.latitude) : null),
      lon: typeof j.longitude === 'number' ? j.longitude : (j.longitude ? Number(j.longitude) : null),
      source: 'ipapi',
    };
  } catch {
    return { ok: false };
  } finally {
    clearTimeout(t);
  }
}

// Fallback local DB (no postal; approximate lat/lon)
function lookupGeoipLite(ip) {
  const g = geoip.lookup(ip);
  if (!g) return { ok: false };
  const [lat, lon] = Array.isArray(g.ll) ? g.ll : [null, null];
  return {
    ok: true,
    country: g.country || null,
    region: Array.isArray(g.region) ? g.region[0] : g.region || null,
    city: g.city || null,
    postal: null, // geoip-lite doesn’t reliably provide postal
    lat, lon,
    source: 'geoip-lite',
  };
}

// ====== ROUTES ======

// Root: single-click logger. Visiting this URL logs and returns a 1×1 pixel (or redirect if configured).
app.get('/', async (req, res) => {
  try {
    // If you require an explicit consent param, enforce it here (optional):
    // const consent = String(req.query.consent || '').toLowerCase() === 'true';
    // if (!consent) return res.status(400).send('Consent required');

    const ip = getClientIp(req);
    const ua = req.headers['user-agent'] || '';
    const priv = isPrivateIp(ip);

    let geo = { ok: false };
    if (GEO_PROVIDER === 'ipapi' && ip) {
      // Try external first
      geo = await lookupIpapi(ip);
      if (!geo.ok && ip) {
        // Fallback local
        geo = lookupGeoipLite(ip);
      }
    } else if (ip) {
      geo = lookupGeoipLite(ip);
    }

    const doc = await Click.create({
      ts: new Date(),
      raw_ip: ip || null,
      is_private: priv,
      ua,
      country: geo.ok ? geo.country : null,
      region:  geo.ok ? geo.region  : null,
      city:    geo.ok ? geo.city    : null,
      postal:  geo.ok ? geo.postal  : null,
      lat:     geo.ok ? geo.lat     : null,
      lon:     geo.ok ? geo.lon     : null,
      source:  geo.ok ? geo.source  : null,
      path: req.originalUrl || '/',
      ref: req.headers.referer || null,
    });

    // Print to server logs (Render → Runtime Logs)
    console.log('Click recorded:', {
      ts: doc.ts,
      ip: doc.raw_ip,
      is_private: doc.is_private,
      country: doc.country, region: doc.region, city: doc.city, postal: doc.postal,
      lat: doc.lat, lon: doc.lon, source: doc.source
    });

    // Response: 1x1 pixel or redirect
    if (REDIRECT_AFTER) {
      return res.redirect(302, REDIRECT_AFTER);
    } else {
      return pixel1x1(res); // tiny transparent PNG
    }
  } catch (e) {
    console.error('Error logging:', e);
    return res.status(500).send('Server error');
  }
});

// Health check
app.get('/api/health', (_req, res) => {
  res.json({ ok: true, db: mongoose.connection.readyState === 1 ? 'connected' : 'not-connected' });
});

// Admin: fetch last 100 logs (token required)
app.get('/admin/logs', async (req, res) => {
  try {
    const token =
      req.query.token ||
      (req.headers.authorization || '').split(' ')[1] ||
      '';
    if (token !== ADMIN_TOKEN) return res.status(401).json({ ok: false, error: 'Unauthorized' });

    const rows = await Click.find().sort({ createdAt: -1 }).limit(100).lean();
    res.json({ ok: true, count: rows.length, rows });
  } catch (e) {
    console.error('Error reading logs:', e);
    res.status(500).json({ ok: false, error: 'Server error' });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Single-click logger running on port ${PORT}`);
});
