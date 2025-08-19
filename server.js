import express from "express";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import cors from "cors";
import geoip from "geoip-lite";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.set("trust proxy", true);
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const LOG_PATH = path.join(__dirname, "logs.jsonl");
const SALT = process.env.IP_HASH_SALT || "change-me-in-env";

if (!fs.existsSync(LOG_PATH)) {
  fs.writeFileSync(LOG_PATH, "", "utf8");
}

function anonymizeIp(ip) {
  if (!ip) return null;
  if (ip.includes(":")) {
    const parts = ip.split(":");
    const anonymized = parts.map((p, i) => (i < 3 ? p : "0")).join(":");
    return anonymized;
  } else {
    const parts = ip.split(".");
    if (parts.length === 4) {
      return `${parts[0]}.${parts[1]}.${parts[2]}.0`;
    }
    return ip;
  }
}

function hashIp(ip) {
  if (!ip) return null;
  return crypto.createHmac("sha256", SALT).update(ip).digest("hex");
}

app.post("/api/record-click", (req, res) => {
  try {
    const { consent, page, action } = req.body || {};
    if (!consent) {
      return res.status(400).json({ ok: false, error: "Consent not provided." });
    }

    const xff = (req.headers["x-forwarded-for"] || "").toString();
    const clientIp = (xff.split(",")[0] || req.ip || "").trim();

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
      geo: geo,
      userAgent: req.headers["user-agent"] || null
    };

    fs.appendFileSync(LOG_PATH, JSON.stringify(record) + "\n", "utf8");
    return res.json({ ok: true, stored: { ts: record.ts, page: record.page, action: record.action, geo: record.geo } });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.get("/api/health", (_req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Consentful analytics server running on http://localhost:${PORT}`);
});
