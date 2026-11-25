# Portfolio - Feature Implementation Guide

## 📋 Übersicht

Dieses Guide zeigt, wie man die geplanten Features implementiert:
1. Email Verification
2. 2FA (TOTP)
3. User Profile
4. Social Login (OAuth)
5. Tailwind CSS UI
6. Swagger API Docs

---

## 1. Email Verification

### Ziel
Benutzer müssen ihre E-Mail bestätigen, um sich registrieren zu können.

### Implementation

**Schritt 1: Route in server.js hinzufügen**

```javascript
// Nach POST /api/register
app.post("/api/verify-email", async (req, res) => {
  const token = String(req.body?.token ?? "");
  const ev = token && db.prepare("SELECT * FROM email_verifications WHERE token_hash = ?")
    .get(hashToken(token));
  
  if (!ev || ev.verified_at !== null || ev.expires_at <= now()) {
    return res.status(400).json({ error: "Verification link invalid or expired" });
  }
  
  db.prepare("UPDATE email_verifications SET verified_at = ? WHERE id = ?")
    .run(now(), ev.id);
  db.prepare("UPDATE users SET email_verified = 1, email_verified_at = ? WHERE id = ?")
    .run(now(), ev.user_id);
  
  res.json({ message: "Email verified successfully" });
});
```

**Schritt 2: Register-Route anpassen**

Wenn User sich registriert:
1. Verification Token generieren
2. In DB speichern (hash only)
3. Verification E-Mail versenden
4. User als "unverified" markieren

**Schritt 3: Login anpassen**

```javascript
// In POST /api/login - before login
if (!user.email_verified) {
  return res.status(403).json({ error: "Please verify your email first" });
}
```

---

## 2. 2FA (TOTP) - Two-Factor Authentication

### Ziel
Zusätzliche Sicherheitsebene mit Authenticator-Apps (Google Authenticator, Authy).

### Implementation

**Schritt 1: 2FA Setup Route**

```javascript
app.post("/api/2fa/setup", (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  
  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.session.userId);
  const secret = speakeasy.generateSecret({
    name: `Portfolio (${user.email})`,
    issuer: "Portfolio",
    length: 32
  });
  
  res.json({
    secret: secret.base32,
    qrCode: await QRCode.toDataURL(secret.otpauth_url)
  });
});
```

**Schritt 2: 2FA Verify Route**

```javascript
app.post("/api/2fa/verify", (req, res) => {
  const { token } = req.body;
  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.session.userId);
  
  if (!speakeasy.totp.verify({ secret: user.totp_secret, token })) {
    return res.status(400).json({ error: "Invalid token" });
  }
  
  db.prepare("UPDATE users SET totp_enabled = 1 WHERE id = ?").run(req.session.userId);
  res.json({ message: "2FA enabled" });
});
```

**Schritt 3: Login mit 2FA**

```javascript
// Nach Password-Verify aber VOR Session erstellen
if (user.totp_enabled) {
  return res.status(203).json({ 
    message: "Enter 2FA token",
    requiresMFA: true,
    tempToken: generateTempToken(user.id)
  });
}
```

---

## 3. User Profile

### Implementation

**Route: GET /api/profile**

```javascript
app.get("/api/profile", (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  
  const profile = db.prepare("SELECT * FROM user_profiles WHERE user_id = ?")
    .get(req.session.userId);
  
  res.json(profile || {});
});
```

**Route: PUT /api/profile**

```javascript
app.put("/api/profile", (req, res) => {
  const { full_name, bio, avatar_url } = req.body;
  
  db.prepare(`
    INSERT INTO user_profiles (user_id, full_name, bio, avatar_url, updated_at)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(user_id) DO UPDATE SET
      full_name = excluded.full_name,
      bio = excluded.bio,
      avatar_url = excluded.avatar_url,
      updated_at = excluded.updated_at
  `).run(req.session.userId, full_name, bio, avatar_url, now());
  
  res.json({ message: "Profile updated" });
});
```

---

## 4. Social Login (OAuth)

### Mit Google

**Package:** `passport-google-oauth20`

**Schritt 1: Passport konfigurieren**

```javascript
import passport from "passport";
import GoogleStrategy from "passport-google-oauth20";

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: `${baseUrl}/auth/google/callback`
}, (accessToken, refreshToken, profile, done) => {
  // Prüfe ob User existiert
  let user = db.prepare("SELECT * FROM users WHERE email = ?").get(profile.emails[0].value);
  
  if (!user) {
    // Neu-Registrierung über OAuth
    db.prepare("INSERT INTO users (email, password_hash, email_verified, password_changed_at, created_at)")
      .run(profile.emails[0].value, "", 1, now(), now());
    user = db.prepare("SELECT * FROM users WHERE email = ?").get(profile.emails[0].value);
  }
  
  // Speichere OAuth Account
  db.prepare("INSERT OR IGNORE INTO oauth_accounts (user_id, provider, provider_id, created_at)")
    .run(user.id, "google", profile.id, now());
  
  return done(null, user);
}));
```

**Schritt 2: Routes**

```javascript
app.get("/auth/google", passport.authenticate("google", { scope: ["email", "profile"] }));

app.get("/auth/google/callback", passport.authenticate("google", { failureRedirect: "/login" }), 
  (req, res) => {
    req.session.userId = req.user.id;
    res.redirect("/");
  }
);
```

---

## 5. Tailwind CSS UI

### Setup

```bash
npm install -D tailwindcss
npx tailwindcss init
```

**tailwind.config.js:**
```javascript
export default {
  content: ["./public/**/*.html"],
  theme: { extend: {} },
  plugins: []
}
```

**package.json script:**
```json
"build": "tailwindcss -i public/input.css -o public/style.css"
```

---

## 6. Swagger API Documentation

### Installation

```bash
npm install swagger-jsdoc swagger-ui-express
```

### Setup

```javascript
import swaggerJsdoc from "swagger-jsdoc";
import swaggerUi from "swagger-ui-express";

const specs = swaggerJsdoc({
  definition: {
    openapi: "3.0.0",
    info: { title: "Portfolio API", version: "1.0.0" },
    servers: [{ url: baseUrl }]
  },
  apis: ["./src/server.js"]
});

app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(specs));
```

---

## 🚀 Deployment: Vercel

### vercel.json

```json
{
  "version": 2,
  "builds": [
    {
      "src": "src/server.js",
      "use": "@vercel/node"
    }
  ],
  "routes": [
    {
      "src": "/(.*)",
      "dest": "src/server.js"
    }
  ],
  "env": {
    "NODE_ENV": "production"
  }
}
```

### Deployment-Schritte

1. `vercel login`
2. `vercel --prod`

---

## 📝 Nächste Schritte

1. **Email Verification** implementieren (1-2 Stunden)
2. **2FA** implementieren (2-3 Stunden)
3. **Profile Pages** erstellen (1-2 Stunden)
4. **Social Login** konfigurieren (1-2 Stunden, benötigt OAuth Keys)
5. **Tailwind CSS** einrichten (1 Stunde)
6. **Swagger Docs** hinzufügen (30 Min)
7. **Tests** aktualisieren
8. **Zu Vercel deployen**

---

## 🔐 Sicherheit

- Alle Tokens werden gehashed gespeichert
- TOTP Secrets sind verschlüsselt
- OAuth Accounts sind mit User verlinkt
- Rate Limiting auf allen kritischen Endpoints
- CSRF Protection mit Session Tokens

