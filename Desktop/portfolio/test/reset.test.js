import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createApp } from "../src/server.js";
import { openDb } from "../src/db.js";

let server, base, db, mail, clock;

beforeEach(async () => {
  db = openDb(":memory:");
  mail = [];
  clock = { t: Date.UTC(2026, 0, 1) };
  const app = createApp({
    db,
    mailer: { sendResetLink: (to, link) => { mail.push({ to, link }); } },
    baseUrl: "http://localhost:3000",
    now: () => clock.t,
  });
  await new Promise((resolve) => { server = app.listen(0, "127.0.0.1", resolve); });
  base = `http://127.0.0.1:${server.address().port}`;
});

afterEach(() => new Promise((resolve) => server.close(resolve)));

/** POST JSON, carrying a cookie jar so sessions work. */
async function post(path, body, jar = {}) {
  const res = await fetch(base + path, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(jar.cookie ? { Cookie: jar.cookie } : {}) },
    body: JSON.stringify(body),
  });
  const set = res.headers.get("set-cookie");
  if (set) jar.cookie = set.split(";")[0];
  return { status: res.status, body: await res.json() };
}

async function me(jar) {
  const res = await fetch(base + "/api/me", { headers: jar.cookie ? { Cookie: jar.cookie } : {} });
  return res.status;
}

const tokenFrom = (link) => new URL(link).searchParams.get("token");

async function register(email = "ali@example.com", password = "eskiSifre1") {
  const r = await post("/api/register", { email, password, confirm: password });
  assert.equal(r.status, 201);
}

test("full reset: old password stops working, new one works", async () => {
  await register();
  const r = await post("/api/forgot-password", { email: "Ali@Example.com " });
  assert.equal(r.status, 200);
  assert.equal(mail.length, 1);
  assert.equal(mail[0].to, "ali@example.com");
  assert.match(mail[0].link, /^http:\/\/localhost:3000\/reset-password\?token=[\w-]{43}$/);

  const reset = await post("/api/reset-password",
    { token: tokenFrom(mail[0].link), password: "yeniSifre22", confirm: "yeniSifre22" });
  assert.equal(reset.status, 200, JSON.stringify(reset.body));

  assert.equal((await post("/api/login", { email: "ali@example.com", password: "eskiSifre1" })).status, 401);
  const jar = {};
  assert.equal((await post("/api/login", { email: "ali@example.com", password: "yeniSifre22" }, jar)).status, 200);
  assert.equal(await me(jar), 200);
});

test("a link works only once", async () => {
  await register();
  await post("/api/forgot-password", { email: "ali@example.com" });
  const token = tokenFrom(mail[0].link);
  assert.equal((await post("/api/reset-password", { token, password: "birinciYeni1", confirm: "birinciYeni1" })).status, 200);
  const again = await post("/api/reset-password", { token, password: "ikinciYeni22", confirm: "ikinciYeni22" });
  assert.equal(again.status, 400);
  assert.match(again.body.error, /geçersiz/);
});

test("expired and made-up tokens are refused", async () => {
  await register();
  await post("/api/forgot-password", { email: "ali@example.com" });
  assert.equal((await post("/api/reset-password", { token: "uydurma", password: "yeniSifre22" })).status, 400);
  assert.equal((await post("/api/reset-password", { token: "", password: "yeniSifre22" })).status, 400);
  clock.t += 30 * 60 * 1000 + 1;
  const late = await post("/api/reset-password",
    { token: tokenFrom(mail[0].link), password: "yeniSifre22", confirm: "yeniSifre22" });
  assert.equal(late.status, 400);
  assert.equal((await post("/api/login", { email: "ali@example.com", password: "eskiSifre1" })).status, 200);
});

test("a newer link cancels the older one", async () => {
  await register();
  await post("/api/forgot-password", { email: "ali@example.com" });
  await post("/api/forgot-password", { email: "ali@example.com" });
  const [first, second] = mail.map((m) => tokenFrom(m.link));
  assert.equal((await post("/api/reset-password", { token: first, password: "yeniSifre22" })).status, 400);
  assert.equal((await post("/api/reset-password", { token: second, password: "yeniSifre22" })).status, 200);
});

test("unknown e-mail gets the same answer and no mail", async () => {
  await register();
  const known = await post("/api/forgot-password", { email: "ali@example.com" });
  const unknown = await post("/api/forgot-password", { email: "kimse@example.com" });
  assert.equal(unknown.status, known.status);
  assert.deepEqual(unknown.body, known.body);
  assert.equal(mail.length, 1);
});

test("weak or mismatched new passwords are refused and keep the link usable", async () => {
  await register();
  await post("/api/forgot-password", { email: "ali@example.com" });
  const token = tokenFrom(mail[0].link);
  assert.equal((await post("/api/reset-password", { token, password: "kisa" })).status, 400);
  assert.equal((await post("/api/reset-password", { token, password: "yeniSifre22", confirm: "farkli123" })).status, 400);
  assert.equal((await post("/api/reset-password", { token, password: "yeniSifre22", confirm: "yeniSifre22" })).status, 200);
});

test("only a hash of the token is stored", async () => {
  await register();
  await post("/api/forgot-password", { email: "ali@example.com" });
  const token = tokenFrom(mail[0].link);
  const rows = db.prepare("SELECT token_hash FROM password_resets").all();
  assert.equal(rows.length, 1);
  assert.notEqual(rows[0].token_hash, token);
  assert.match(rows[0].token_hash, /^[0-9a-f]{64}$/);
});

test("changing the password ends sessions that started before it", async () => {
  await register();
  const jar = {};
  await post("/api/login", { email: "ali@example.com", password: "eskiSifre1" }, jar);
  assert.equal(await me(jar), 200);
  clock.t += 1000;
  await post("/api/forgot-password", { email: "ali@example.com" });
  await post("/api/reset-password", { token: tokenFrom(mail[0].link), password: "yeniSifre22" });
  assert.equal(await me(jar), 401);
});

test("too many reset requests are slowed down", async () => {
  await register();
  const statuses = [];
  for (let i = 0; i < 6; i++) statuses.push((await post("/api/forgot-password", { email: "ali@example.com" })).status);
  assert.deepEqual(statuses, [200, 200, 200, 200, 200, 429]);
  clock.t += 15 * 60 * 1000 + 1;
  assert.equal((await post("/api/forgot-password", { email: "ali@example.com" })).status, 200);
});

test("pages are served and do not leak the token through Referer", async () => {
  for (const page of ["/login", "/register", "/forgot-password", "/reset-password?token=x"]) {
    const res = await fetch(base + page);
    assert.equal(res.status, 200, page);
    assert.equal(res.headers.get("referrer-policy"), "no-referrer");
  }
  const login = await (await fetch(base + "/login")).text();
  assert.match(login, /href="\/forgot-password">Şifremi unuttum</);
});
