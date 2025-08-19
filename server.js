import express from "express";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import geoip from "geoip-lite";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.set("trust proxy", true); // trust X-Forwarded-For when behind proxy
app.use(express.json());

const LOG_PATH = path.join(__dirname, "logs.jsonl");
const SALT = process.env.IP_HASH_SALT || "change-me-in-env";

// make sure the file exists locally
if (!fs.existsSync(LOG_PATH)) fs.writeFileSync(LOG_PATH, "", "utf8");

function anonymizeIp(ip) {
  if (!ip) return null;
  if (ip.includes(":")) {
    // IPv6: zero after 3 hextets
    const parts = ip.split(":");
    return parts.map((p, i) => (i < 3 ? p : "0")).join(":");
  } else {
    // IPv4: zero last octet
    const parts = ip.split(".");
    if (parts.length === 4) return `${parts[0]}.${parts[1]}.${parts[2]}.0`;
    return ip;
  }
}

function hashIp(ip) {
  if (!ip) return null;
  return crypto.createHmac("sha256", SALT).update(ip).digest("hex");
}

// One-click logging endpoint
app.all("/click", (req, res) => {
  try {
    const payload = req.method === "GET" ? req.query : (req.body || {});
    const { action, page } = payload;
    const consent = String(payload.consent || "").toLowerCase() === "true";

    if (!consent) {
      return res.status(400).json({ ok: false, error: "Consent not provided (consent=true required)." });
    }

    // get IP
    const xff = (req.headers["x-forwarded-for"] || "").toString();
    const clientIp = (xff.split(",")[0] || req.ip || "").trim();

    // skip private ranges
    const isPrivate =
      /^127\.|^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[0-1])\./.test(clientIp) ||
      clientIp === "::1";

    const coarseIp = isPrivate ? null : anonymizeIp(clientIp);
    const hashedIp = isPrivate ? null : hashIp(clientIp);

    let geo = null;
    if (!isPrivate && clientIp) {
      const g = geoip.lookup(clientIp);
      if (g) {
        geo = {
          country: g.country || null,
          region: Array.isArray(g.region) ? g.region[0] : g.region || null,
          city: g.city || null
        };
      }
    }

    const record = {
      ts: new Date().toISOString(),
      page: page || null,
      action: action || "click",
      ip_anonymized: coarseIp,
      ip_hash: hashedIp,
      geo,
      userAgent: req.headers["user-agent"] || null
    };

    // Write to file (local runs)
    try {
      fs.appendFileSync(LOG_PATH, JSON.stringify(record) + "\n", "utf8");
    } catch (err) {
      // Ignore if fs is not writable on Render
    }

    // 🔥 Print to Render Logs
    console.log("Click recorded:", record);

    return res.json({ ok: true, stored: record });
  } catch (err) {
    console.error("Error recording click:", err);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

// health check
app.get("/", (_req, res) => res.send("Logger is running. Use /click?consent=true&action=test&page=/"));
app.get("/api/health", (_req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Logger running on port ${PORT}`);
});
