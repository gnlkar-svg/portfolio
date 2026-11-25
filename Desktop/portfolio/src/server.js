import path from "node:path";
import { fileURLToPath } from "node:url";
import { randomBytes } from "node:crypto";
import express from "express";
import session from "express-session";
import { openDb } from "./db.js";
import { createMailer } from "./mailer.js";
import {
  checkNewPassword, hashPassword, hashToken, newResetToken, verifyPassword,
} from "./passwords.js";

const PUBLIC_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "public");
const RESET_TTL_MS = 30 * 60 * 1000;
const LIMIT_WINDOW_MS = 15 * 60 * 1000;
const LIMIT_MAX = 5;
const SAME_ANSWER = "Bu e-posta kayıtlıysa şifre sıfırlama bağlantısı gönderildi. Gelen kutunu kontrol et.";
const BAD_LINK = "Bağlantı geçersiz veya süresi dolmuş. Yeni bir sıfırlama bağlantısı iste.";

function normalizeEmail(value) {
  const email = String(value ?? "").trim().toLowerCase();
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254 ? email : null;
}

/** Counts requests per key in a sliding window (in memory). */
function rateLimiter(now) {
  const hits = new Map();
  return (key) => {
    const t = now();
    const recent = (hits.get(key) || []).filter((x) => t - x < LIMIT_WINDOW_MS);
    recent.push(t);
    hits.set(key, recent);
    return recent.length <= LIMIT_MAX;
  };
}

export function createApp({
  db = openDb(":memory:"),
  mailer = createMailer(),
  baseUrl = "http://localhost:3000",
  sessionSecret = randomBytes(32).toString("hex"),
  now = () => Date.now(),
} = {}) {
  const app = express();
  const allow = rateLimiter(now);
  const q = {
    userByEmail: db.prepare("SELECT * FROM users WHERE email = ?"),
    userById: db.prepare("SELECT * FROM users WHERE id = ?"),
    addUser: db.prepare(
      "INSERT INTO users (email, password_hash, password_changed_at, created_at) VALUES (?, ?, ?, ?)"),
    setPassword: db.prepare("UPDATE users SET password_hash = ?, password_changed_at = ? WHERE id = ?"),
    closeOpenResets: db.prepare(
      "UPDATE password_resets SET used_at = ? WHERE user_id = ? AND used_at IS NULL"),
    addReset: db.prepare(
      "INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (?, ?, ?)"),
    resetByHash: db.prepare("SELECT * FROM password_resets WHERE token_hash = ?"),
    useReset: db.prepare("UPDATE password_resets SET used_at = ? WHERE id = ? AND used_at IS NULL"),
  };

  app.disable("x-powered-by");
  app.use((req, res, next) => {
    // The reset token is in the URL: never send it on to other sites.
    res.set("Referrer-Policy", "no-referrer");
    res.set("X-Content-Type-Options", "nosniff");
    next();
  });
  app.use(express.json({ limit: "10kb" }));
  app.use(session({
    name: "sid",
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: "lax", secure: baseUrl.startsWith("https://") },
  }));

  app.post("/api/register", async (req, res) => {
    const email = normalizeEmail(req.body?.email);
    if (!email) return res.status(400).json({ error: "Geçerli bir e-posta adresi yaz." });
    const problem = checkNewPassword(req.body?.password, req.body?.confirm);
    if (problem) return res.status(400).json({ error: problem });
    if (q.userByEmail.get(email)) return res.status(409).json({ error: "Bu e-posta ile zaten bir hesap var." });
    const t = now();
    q.addUser.run(email, await hashPassword(req.body.password), t, t);
    res.status(201).json({ message: "Hesap oluşturuldu. Şimdi giriş yapabilirsin." });
  });

  app.post("/api/login", async (req, res) => {
    const email = normalizeEmail(req.body?.email);
    const user = email && q.userByEmail.get(email);
    const ok = user && (await verifyPassword(String(req.body?.password ?? ""), user.password_hash));
    if (!ok) return res.status(401).json({ error: "E-posta veya şifre hatalı." });
    req.session.regenerate((err) => {
      if (err) return res.status(500).json({ error: "Oturum açılamadı." });
      req.session.userId = user.id;
      req.session.loginAt = now();
      res.json({ message: "Giriş yapıldı.", email: user.email });
    });
  });

  app.post("/api/logout", (req, res) => {
    req.session.destroy(() => res.json({ message: "Çıkış yapıldı." }));
  });

  app.get("/api/me", (req, res) => {
    const user = req.session.userId && q.userById.get(req.session.userId);
    // A password change ends every session that started before it.
    if (!user || req.session.loginAt < user.password_changed_at) {
      return req.session.destroy(() => res.status(401).json({ error: "Giriş yapılmamış." }));
    }
    res.json({ email: user.email });
  });

  app.post("/api/forgot-password", (req, res) => {
    const email = normalizeEmail(req.body?.email);
    if (!email) return res.status(400).json({ error: "Geçerli bir e-posta adresi yaz." });
    if (!allow(`ip:${req.ip}`) || !allow(`email:${email}`)) {
      return res.status(429).json({ error: "Çok fazla istek. 15 dakika sonra tekrar dene." });
    }
    const user = q.userByEmail.get(email);
    if (user) {
      const token = newResetToken();
      const t = now();
      q.closeOpenResets.run(t, user.id);  // only the newest link works
      q.addReset.run(user.id, hashToken(token), t + RESET_TTL_MS);
      const link = `${baseUrl.replace(/\/$/, "")}/reset-password?token=${encodeURIComponent(token)}`;
      // Not awaited: the answer must take the same time whether or not the e-mail exists.
      Promise.resolve(mailer.sendResetLink(user.email, link))
        .catch((e) => console.error("Sıfırlama e-postası gönderilemedi:", e.message));
    }
    res.json({ message: SAME_ANSWER });
  });

  app.post("/api/reset-password", async (req, res) => {
    const token = String(req.body?.token ?? "");
    const reset = token && q.resetByHash.get(hashToken(token));
    if (!reset || reset.used_at !== null || reset.expires_at <= now()) {
      return res.status(400).json({ error: BAD_LINK });
    }
    const problem = checkNewPassword(req.body?.password, req.body?.confirm);
    if (problem) return res.status(400).json({ error: problem });
    const hash = await hashPassword(req.body.password);
    const t = now();
    // Mark used first; if another request already used it, stop.
    if (Number(q.useReset.run(t, reset.id).changes) !== 1) {
      return res.status(400).json({ error: BAD_LINK });
    }
    q.setPassword.run(hash, t, reset.user_id);
    q.closeOpenResets.run(t, reset.user_id);
    req.session.destroy(() => res.json({ message: "Şifren değişti. Yeni şifrenle giriş yapabilirsin." }));
  });

  app.get("/", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "index.html")));
  app.get("/reset-password", (req, res) => res.sendFile(path.join(PUBLIC_DIR, "reset-password.html")));
  app.use(express.static(PUBLIC_DIR, { extensions: ["html"] }));

  app.use((err, req, res, next) => {
    if (err.type === "entity.parse.failed") return res.status(400).json({ error: "İstek okunamadı." });
    console.error(err);
    res.status(500).json({ error: "Sunucu hatası." });
  });
  return app;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT || 3000);
  const baseUrl = process.env.BASE_URL || `http://localhost:${port}`;
  if (!process.env.SESSION_SECRET) {
    console.warn("SESSION_SECRET yok: geçici bir anahtar kullanılıyor (sunucu yeniden başlayınca oturumlar düşer).");
  }
  const app = createApp({
    db: openDb(process.env.DB_PATH || path.join(PUBLIC_DIR, "..", "data.db")),
    mailer: createMailer(),
    baseUrl,
    sessionSecret: process.env.SESSION_SECRET,
  });
  // Express 5 passes a failed listen (e.g. port in use) to this callback.
  app.listen(port, (err) => {
    if (err) {
      console.error(err.code === "EADDRINUSE"
        ? `${port} numaralı port kullanımda. .env dosyasında PORT ile başka bir port seç (ör. PORT=3100).`
        : `Sunucu başlatılamadı: ${err.message}`);
      process.exit(1);
    }
    console.log(`Sunucu hazır: ${baseUrl}/login`);
  });
}
