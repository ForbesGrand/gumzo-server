// Gumzo server v3: accounts, phone/email, profile pictures, files, WhatsApp-style ticks, password reset, shop orders.
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");
const { WebSocketServer } = require("ws");

const PORT = process.env.PORT || 3000;
if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is missing. Add it in Render > Environment.");
  process.exit(1);
}
const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 5 });
pool.on("error", (e) => console.error("Database connection error:", e.message));
const q = (sql, params) => pool.query(sql, params);

const MAX_FILE = 8 * 1024 * 1024;          // biggest photo/video/file: 8 MB
const MAX_AVATAR = 300 * 1024;             // profile picture: 300 KB (the app shrinks it first)
const MAX_USER_STORE = 150 * 1024 * 1024;  // total files one person can send: 150 MB
const INLINE = new Set(["image/jpeg", "image/png", "image/gif", "image/webp", "video/mp4", "video/webm", "video/quicktime", "audio/mpeg", "audio/mp4", "audio/ogg", "audio/webm", "audio/wav"]);

// Shop catalog (edit these to match your real products)
const products = [
  { id: 1, name: "Bluetooth speaker", price: 45000, stock: 12 },
  { id: 2, name: "Phone charger 20W", price: 15000, stock: 40 },
  { id: 3, name: "Wireless earbuds", price: 60000, stock: 8 },
];

const online = new Map();   // name -> { ws, lowData }
const fails = new Map();    // ip -> times of wrong passwords
const hits = new Map();     // key -> times (password reset limits)

function json(res, code, data) {
  res.writeHead(code, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}
function readBody(req) {
  return new Promise((resolve) => {
    let b = "";
    req.on("data", (c) => { b += c; if (b.length > 20000) req.destroy(); });
    req.on("end", () => { try { resolve(JSON.parse(b)); } catch { resolve({}); } });
  });
}
function readRaw(req, max) {
  return new Promise((resolve) => {
    const parts = []; let n = 0, over = false;
    req.on("data", (c) => { n += c.length; if (n > max) { over = true; return; } parts.push(c); });
    req.on("end", () => resolve(over ? null : Buffer.concat(parts)));
    req.on("error", () => resolve(null));
  });
}
const getIp = (req) => String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();

// ---------- Passwords: never stored as text, only as a salted scrypt hash ----------
function hash(pw) {
  const salt = crypto.randomBytes(16).toString("hex");
  return salt + ":" + crypto.scryptSync(pw, salt, 64).toString("hex");
}
function check(pw, stored) {
  const [salt, h] = stored.split(":");
  const a = Buffer.from(h, "hex");
  const b = crypto.scryptSync(pw, salt, 64);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function tooMany(ip) {
  const now = Date.now();
  const list = (fails.get(ip) || []).filter((t) => now - t < 15 * 60 * 1000);
  fails.set(ip, list);
  return list.length >= 10;
}
function noteFail(ip) { const l = fails.get(ip) || []; l.push(Date.now()); fails.set(ip, l); }
// Counts every call. Returns true when the limit is passed.
function hit(key, max, windowMs) {
  const now = Date.now();
  const list = (hits.get(key) || []).filter((t) => now - t < windowMs);
  list.push(now);
  hits.set(key, list);
  return list.length > max;
}

// ---------- Phone, email, names ----------
function normPhone(s) {
  s = String(s || "").replace(/[\s\-().]/g, "");
  if (!s) return null;
  if (s.startsWith("00")) s = "+" + s.slice(2);
  else if (s.startsWith("0")) s = "+255" + s.slice(1);          // local Tanzania number
  else if (/^\d{9}$/.test(s)) s = "+255" + s;
  else if (/^255\d{9}$/.test(s)) s = "+" + s;
  return /^\+\d{8,15}$/.test(s) ? s : null;
}
const goodEmail = (s) => s.length <= 100 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
const safeName = (s) => String(s || "file").replace(/[\\/:*?"<>|\u0000-\u001f]/g, "_").slice(0, 100) || "file";

// ---------- Sending codes ----------
async function sendEmail(to, subject, text) {
  if (!process.env.BREVO_API_KEY || !process.env.MAIL_FROM) return false;
  try {
    const r = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: { "api-key": process.env.BREVO_API_KEY, "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ sender: { name: "Gumzo", email: process.env.MAIL_FROM }, to: [{ email: to }], subject, textContent: text }),
    });
    if (!r.ok) { console.error("Email failed:", r.status, await r.text()); return false; }
    return true;
  } catch (e) { console.error("Email failed:", e.message); return false; }
}
async function sendSms(to, text) {
  if (!process.env.AT_API_KEY || !process.env.AT_USERNAME) return false;
  try {
    const base = process.env.AT_USERNAME === "sandbox" ? "https://api.sandbox.africastalking.com" : "https://api.africastalking.com";
    const r = await fetch(base + "/version1/messaging", {
      method: "POST",
      headers: { apiKey: process.env.AT_API_KEY, Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ username: process.env.AT_USERNAME, to, message: text }).toString(),
    });
    if (!r.ok) { console.error("SMS failed:", r.status, await r.text()); return false; }
    return true;
  } catch (e) { console.error("SMS failed:", e.message); return false; }
}

async function setup() {
  await q("create table if not exists users(name text primary key, hash text not null, created timestamptz default now())");
  await q("create table if not exists sessions(token text primary key, name text not null, created timestamptz default now())");
  await q("create table if not exists messages(id bigserial primary key, from_user text not null, to_user text not null, text text not null, kind text not null default 'msg', created timestamptz default now())");
  await q("create index if not exists msg_from on messages(from_user)");
  await q("create index if not exists msg_to on messages(to_user)");
  await q("create sequence if not exists order_seq");
  await q("create table if not exists reads(name text not null, other text not null, last_id bigint not null default 0, primary key(name, other))");

  // New in v3
  const had = await q("select 1 from information_schema.columns where table_name='messages' and column_name='delivered_at'");
  await q("alter table users add column if not exists phone text");
  await q("alter table users add column if not exists email text");
  await q("alter table users add column if not exists show_phone boolean not null default false");
  await q("alter table users add column if not exists avatar bytea");
  await q("alter table users add column if not exists avatar_mime text");
  await q("alter table users add column if not exists avatar_v int not null default 0");
  await q("create unique index if not exists users_phone_u on users(phone) where phone is not null");
  await q("create unique index if not exists users_email_u on users(email) where email is not null");
  await q("alter table messages add column if not exists file_id bigint");
  await q("alter table messages add column if not exists delivered_at timestamptz");
  await q("alter table messages add column if not exists read_at timestamptz");
  if (!had.rows.length) await q("update messages set delivered_at=created, read_at=created"); // old messages count as read
  await q("create table if not exists files(id bigserial primary key, owner text not null, to_user text not null, name text not null, mime text not null, size int not null, data bytea not null, created timestamptz default now())");
  await q("create table if not exists resets(name text primary key, code_hash text not null, expires timestamptz not null, tries int not null default 0)");

  // The shop account is created from the SHOP_PASSWORD you set in Render. Nobody can sign up as "shop".
  if (process.env.SHOP_PASSWORD) {
    await q("insert into users(name,hash) values('shop',$1) on conflict (name) do update set hash = excluded.hash", [hash(process.env.SHOP_PASSWORD)]);
  }
}

const staticFiles = {
  "/": ["index.html", "text/html; charset=utf-8"],
  "/manifest.json": ["manifest.json", "application/manifest+json"],
  "/sw.js": ["sw.js", "text/javascript"],
  "/icon-192.png": ["icon-192.png", "image/png"],
  "/icon-512.png": ["icon-512.png", "image/png"],
};

async function authUser(req, url) {
  const h = String(req.headers.authorization || "");
  const t = h.startsWith("Bearer ") ? h.slice(7) : String(url.searchParams.get("token") || "");
  if (!t) return null;
  const r = await q("select name from sessions where token=$1", [t]);
  return r.rows.length ? r.rows[0].name : null;
}

function serveBinary(req, res, buf, mime, name, cache) {
  const inline = INLINE.has(mime);
  const head = {
    "Content-Type": inline ? mime : "application/octet-stream",
    "Accept-Ranges": "bytes",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "sandbox",
    "Cache-Control": cache,
    "Content-Disposition": (inline ? "inline" : "attachment") + "; filename*=UTF-8''" + encodeURIComponent(name || "file"),
  };
  const total = buf.length;
  const m = /^bytes=(\d*)-(\d*)$/.exec(String(req.headers.range || ""));
  if (m && (m[1] || m[2])) {
    let s, e;
    if (m[1] === "") { s = Math.max(total - parseInt(m[2]), 0); e = total - 1; }
    else { s = parseInt(m[1]); e = m[2] === "" ? total - 1 : Math.min(parseInt(m[2]), total - 1); }
    if (s > e || s >= total) { res.writeHead(416, { "Content-Range": "bytes */" + total }); return res.end(); }
    res.writeHead(206, { ...head, "Content-Range": "bytes " + s + "-" + e + "/" + total, "Content-Length": e - s + 1 });
    return res.end(buf.subarray(s, e + 1));
  }
  res.writeHead(200, { ...head, "Content-Length": total });
  res.end(buf);
}

// Save a message, push it to the receiver if online (that makes it "delivered").
async function deliver(from, to, text, kind, fileId, file) {
  const u = online.get(to);
  const live = !!(u && u.ws.readyState === 1);
  const r = await q(
    "insert into messages(from_user,to_user,text,kind,file_id,delivered_at) values($1,$2,$3,$4,$5," + (live ? "now()" : "null") + ") returning id, created",
    [from, to, text, kind, fileId]
  );
  const id = Number(r.rows[0].id), at = r.rows[0].created;
  if (live) u.ws.send(JSON.stringify({ type: "msg", id, from, text, kind, file: file || null, at }));
  return { id, at, st: live ? "delivered" : "sent" };
}

async function handler(req, res) {
  const url = new URL(req.url, "http://localhost");
  const p = url.pathname;

  if (staticFiles[p]) {
    res.writeHead(200, { "Content-Type": staticFiles[p][1], "Cache-Control": "no-cache" });
    return res.end(fs.readFileSync(path.join(__dirname, staticFiles[p][0])));
  }
  if (p === "/api/products") return json(res, 200, products);

  // ---------- Profile pictures (shown to everyone) ----------
  let m = p.match(/^\/avatar\/([a-z0-9_]{3,20})$/);
  if (m) {
    const r = await q("select avatar, avatar_mime from users where name=$1", [m[1]]);
    if (!r.rows.length || !r.rows[0].avatar) { res.writeHead(404); return res.end(); }
    return serveBinary(req, res, r.rows[0].avatar, r.rows[0].avatar_mime || "image/jpeg", "avatar", url.searchParams.get("v") ? "public, max-age=31536000, immutable" : "no-cache");
  }

  // ---------- Sign up and log in ----------
  if (req.method === "POST" && (p === "/api/register" || p === "/api/login")) {
    const ip = getIp(req);
    if (tooMany(ip)) return json(res, 429, { error: "Too many wrong tries. Wait 15 minutes." });
    const b = await readBody(req);
    const name = String(b.name || "").trim().toLowerCase();
    const pw = String(b.password || "");
    try {
      let who = name;
      if (p === "/api/register") {
        if (!/^[a-z0-9_]{3,20}$/.test(name)) return json(res, 400, { error: "Name: 3 to 20 letters, numbers or _" });
        if (name === "shop") return json(res, 400, { error: "That name is reserved" });
        if (pw.length < 6) return json(res, 400, { error: "Password needs at least 6 characters" });
        let phone = null, email = null;
        if (String(b.phone || "").trim()) { phone = normPhone(b.phone); if (!phone) return json(res, 400, { error: "That phone number doesn't look right" }); }
        if (String(b.email || "").trim()) { email = String(b.email).trim().toLowerCase(); if (!goodEmail(email)) return json(res, 400, { error: "That email doesn't look right" }); }
        try {
          const r = await q("insert into users(name,hash,phone,email) values($1,$2,$3,$4) on conflict (name) do nothing returning name", [name, hash(pw), phone, email]);
          if (!r.rows.length) return json(res, 409, { error: "That name is taken. Try another." });
        } catch (e) {
          if (e.code === "23505") return json(res, 409, { error: /phone/.test(e.constraint || "") ? "That phone number is already used by another account" : "That email is already used by another account" });
          throw e;
        }
      } else {
        // You can log in with your name, your phone number or your email.
        const ph = normPhone(name);
        const r = await q("select name, hash from users where name=$1 or email=$1 or phone=$2 limit 5", [name, ph]);
        const row = r.rows.find((x) => check(pw, x.hash));
        if (!row) { noteFail(ip); return json(res, 401, { error: "Wrong name or password" }); }
        who = row.name;
      }
      const token = crypto.randomBytes(32).toString("hex");
      await q("insert into sessions(token,name) values($1,$2)", [token, who]);
      return json(res, 200, { token, name: who });
    } catch (e) {
      console.error(e);
      return json(res, 500, { error: "Server problem. Try again in a moment." });
    }
  }
  if (req.method === "POST" && p === "/api/logout") {
    const b = await readBody(req);
    try { await q("delete from sessions where token=$1", [String(b.token || "")]); } catch (e) {}
    return json(res, 200, { ok: true });
  }

  // ---------- Forgot password ----------
  if (req.method === "POST" && p === "/api/forgot") {
    const ip = getIp(req);
    if (hit("f:" + ip, 6, 15 * 60 * 1000)) return json(res, 429, { error: "Too many tries. Wait 15 minutes." });
    const b = await readBody(req);
    const id = String(b.id || "").trim().toLowerCase();
    const same = { ok: true, message: "If that account exists and has an email or phone number saved, a code was sent. It works for 15 minutes." };
    if (!id) return json(res, 400, { error: "Type your name, phone number or email" });
    try {
      const r = await q("select name, email, phone from users where name=$1 or email=$1 or phone=$2 limit 1", [id, normPhone(id)]);
      const u = r.rows[0];
      if (u && u.name !== "shop" && !hit("n:" + u.name, 3, 15 * 60 * 1000)) {
        const code = String(crypto.randomInt(100000, 1000000));
        const ch = crypto.createHash("sha256").update(u.name + ":" + code).digest("hex");
        await q("insert into resets(name,code_hash,expires,tries) values($1,$2,now()+interval '15 minutes',0) on conflict (name) do update set code_hash=excluded.code_hash, expires=excluded.expires, tries=0", [u.name, ch]);
        const msg = "Your Gumzo code is " + code + ". It works for 15 minutes. If you did not ask for it, ignore this message.";
        let sent = false;
        if (u.email) sent = await sendEmail(u.email, "Your Gumzo password code", msg);
        if (!sent && u.phone) sent = await sendSms(u.phone, msg);
        if (!sent) console.error("Reset code for " + u.name + " could not be sent (no email/SMS set up or sending failed).");
      }
      return json(res, 200, same);
    } catch (e) { console.error(e); return json(res, 500, { error: "Server problem. Try again in a moment." }); }
  }
  if (req.method === "POST" && p === "/api/reset") {
    const ip = getIp(req);
    if (hit("r:" + ip, 15, 15 * 60 * 1000)) return json(res, 429, { error: "Too many tries. Wait 15 minutes." });
    const b = await readBody(req);
    const id = String(b.id || "").trim().toLowerCase();
    const code = String(b.code || "").trim();
    const pw = String(b.password || "");
    const bad = { error: "Wrong or expired code" };
    if (pw.length < 6) return json(res, 400, { error: "Password needs at least 6 characters" });
    try {
      const r = await q("select name from users where name=$1 or email=$1 or phone=$2 limit 1", [id, normPhone(id)]);
      if (!r.rows.length || r.rows[0].name === "shop") return json(res, 400, bad);
      const name = r.rows[0].name;
      const rs = await q("select code_hash, expires, tries from resets where name=$1", [name]);
      const row = rs.rows[0];
      if (!row || new Date(row.expires) < new Date() || row.tries >= 5) return json(res, 400, bad);
      const a = Buffer.from(row.code_hash, "hex");
      const c = crypto.createHash("sha256").update(name + ":" + code).digest();
      if (a.length !== c.length || !crypto.timingSafeEqual(a, c)) {
        await q("update resets set tries=tries+1 where name=$1", [name]);
        return json(res, 400, bad);
      }
      await q("update users set hash=$1 where name=$2", [hash(pw), name]);
      await q("delete from resets where name=$1", [name]);
      await q("delete from sessions where name=$1", [name]); // log out all old devices
      return json(res, 200, { ok: true });
    } catch (e) { console.error(e); return json(res, 500, { error: "Server problem. Try again in a moment." }); }
  }

  // ---------- Everything below needs you to be logged in ----------
  if (p.startsWith("/api/")) {
    let user = null;
    try { user = await authUser(req, url); } catch (e) { return json(res, 500, { error: "Server problem" }); }
    if (!user) return json(res, 401, { error: "Please log in again" });

    if (p === "/api/me") {
      const r = await q("select name, phone, email, show_phone, avatar_v from users where name=$1", [user]);
      const x = r.rows[0];
      return json(res, 200, { name: x.name, phone: x.phone, email: x.email, show_phone: x.show_phone, av: x.avatar_v });
    }

    if (p === "/api/find") {
      const s = String(url.searchParams.get("q") || "").trim().toLowerCase();
      const r = await q("select name, avatar_v, phone, show_phone from users where name=$1 or (show_phone and phone=$2) order by (name=$1) desc limit 1", [s, normPhone(s)]);
      if (!r.rows.length) return json(res, 200, { found: false });
      const x = r.rows[0];
      return json(res, 200, { found: true, name: x.name, av: x.avatar_v, phone: x.show_phone ? x.phone : null });
    }

    if (p === "/api/user") {
      const r = await q("select name, avatar_v, phone, show_phone from users where name=$1", [String(url.searchParams.get("name") || "").toLowerCase()]);
      if (!r.rows.length) return json(res, 404, { error: "No such user" });
      const x = r.rows[0];
      return json(res, 200, { name: x.name, av: x.avatar_v, phone: x.show_phone ? x.phone : null });
    }

    if (req.method === "POST" && p === "/api/profile") {
      const b = await readBody(req);
      const cur = (await q("select phone, email, show_phone from users where name=$1", [user])).rows[0];
      let phone = cur.phone, email = cur.email, show = cur.show_phone;
      if ("phone" in b) {
        const s = String(b.phone || "").trim();
        if (!s) phone = null; else { phone = normPhone(s); if (!phone) return json(res, 400, { error: "That phone number doesn't look right" }); }
      }
      if ("email" in b) {
        const s = String(b.email || "").trim().toLowerCase();
        if (!s) email = null; else { if (!goodEmail(s)) return json(res, 400, { error: "That email doesn't look right" }); email = s; }
      }
      if ("show_phone" in b) show = !!b.show_phone;
      try {
        if (b.removeAvatar) await q("update users set avatar=null, avatar_mime=null, avatar_v=avatar_v+1 where name=$1", [user]);
        await q("update users set phone=$1, email=$2, show_phone=$3 where name=$4", [phone, email, show, user]);
      } catch (e) {
        if (e.code === "23505") return json(res, 409, { error: /phone/.test(e.constraint || "") ? "That phone number is already used by another account" : "That email is already used by another account" });
        throw e;
      }
      return json(res, 200, { ok: true, phone, email, show_phone: show });
    }

    if (req.method === "POST" && p === "/api/avatar") {
      const mime = String(req.headers["content-type"] || "").split(";")[0].toLowerCase();
      if (!["image/jpeg", "image/png", "image/webp"].includes(mime)) return json(res, 400, { error: "Please choose a photo (JPG or PNG)" });
      if (parseInt(req.headers["content-length"] || "0") > MAX_AVATAR) return json(res, 413, { error: "Photo is too big" });
      const buf = await readRaw(req, MAX_AVATAR);
      if (!buf || !buf.length) return json(res, 413, { error: "Photo is too big" });
      const r = await q("update users set avatar=$1, avatar_mime=$2, avatar_v=avatar_v+1 where name=$3 returning avatar_v", [buf, mime, user]);
      return json(res, 200, { ok: true, av: r.rows[0].avatar_v });
    }

    if (req.method === "POST" && p === "/api/upload") {
      const to = String(req.headers["x-to"] || "").toLowerCase();
      let fname = "file";
      try { fname = safeName(decodeURIComponent(String(req.headers["x-filename"] || "file"))); } catch (e) {}
      const mime = (String(req.headers["content-type"] || "application/octet-stream").split(";")[0].toLowerCase().trim() || "application/octet-stream").slice(0, 100);
      if (parseInt(req.headers["content-length"] || "0") > MAX_FILE + 1024) {
        res.writeHead(413, { "Content-Type": "application/json", Connection: "close" });
        return res.end(JSON.stringify({ error: "File is too big. The limit is 8 MB." }));
      }
      const buf = await readRaw(req, MAX_FILE);
      if (!buf) return json(res, 413, { error: "File is too big. The limit is 8 MB." });
      if (!buf.length) return json(res, 400, { error: "That file is empty" });
      if (to === user) return json(res, 400, { error: "You cannot send files to yourself" });
      const ex = await q("select 1 from users where name=$1", [to]);
      if (!ex.rows.length) return json(res, 404, { error: "No user called " + to });
      const used = await q("select coalesce(sum(size),0)::bigint as n from files where owner=$1", [user]);
      if (Number(used.rows[0].n) + buf.length > MAX_USER_STORE) return json(res, 400, { error: "You have reached the file limit for this account" });
      const f = await q("insert into files(owner,to_user,name,mime,size,data) values($1,$2,$3,$4,$5,$6) returning id", [user, to, fname, mime, buf.length, buf]);
      const file = { id: Number(f.rows[0].id), name: fname, mime, size: buf.length };
      const d = await deliver(user, to, "", "file", file.id, file);
      return json(res, 200, { ok: true, id: d.id, at: d.at, st: d.st, file });
    }

    m = p.match(/^\/api\/file\/(\d+)$/);
    if (m) {
      const r = await q("select name, mime, data, owner, to_user from files where id=$1", [m[1]]);
      const f = r.rows[0];
      if (!f) return json(res, 404, { error: "File not found" });
      if (user !== f.owner && user !== f.to_user) return json(res, 403, { error: "Not allowed" });
      return serveBinary(req, res, f.data, f.mime, f.name, "private, max-age=86400");
    }
  }
  json(res, 404, { error: "not found" });
}

const server = http.createServer((req, res) => {
  handler(req, res).catch((e) => {
    console.error(e);
    try { json(res, 500, { error: "Server problem. Try again in a moment." }); } catch (e2) {}
  });
});

// ---------- Chat (WebSocket) ----------
const wss = new WebSocketServer({ server, perMessageDeflate: true, maxPayload: 100000 });

wss.on("connection", (ws) => {
  let name = null;
  const fail = (text) => ws.send(JSON.stringify({ type: "error", text }));
  const send = (o) => { if (ws.readyState === 1) ws.send(JSON.stringify(o)); };

  ws.on("message", async (raw) => {
    try {
      let m;
      try { m = JSON.parse(raw); } catch { return; }

      if (m.type === "join") {
        const r = await q("select name from sessions where token=$1", [String(m.token || "")]);
        if (!r.rows.length) return send({ type: "auth" });
        name = r.rows[0].name;
        online.set(name, { ws, lowData: !!m.lowData });
        send({ type: "joined", name });

        // Everything waiting for this person is now "delivered": tell the senders (second grey tick).
        const dv = await q("update messages set delivered_at=now() where to_user=$1 and delivered_at is null returning id, from_user", [name]);
        const by = {};
        dv.rows.forEach((x) => { (by[x.from_user] = by[x.from_user] || []).push(Number(x.id)); });
        for (const s in by) {
          const u = online.get(s);
          if (u && u.ws.readyState === 1) u.ws.send(JSON.stringify({ type: "receipt", by: name, status: "delivered", ids: by[s] }));
        }

        const h = await q(
          'select m.id, m.from_user as "from", m.to_user as "to", m.text, m.kind, m.created as at, m.delivered_at, m.read_at, f.id as fid, f.name as fname, f.mime as fmime, f.size as fsize ' +
          "from messages m left join files f on f.id=m.file_id where m.from_user=$1 or m.to_user=$1 order by m.id desc limit 300", [name]);
        const un = await q("select m.from_user as other, count(*)::int as n from messages m left join reads r on r.name=$1 and r.other=m.from_user where m.to_user=$1 and m.id > coalesce(r.last_id,0) group by m.from_user", [name]);
        const unread = {};
        un.rows.forEach((x) => { unread[x.other] = x.n; });
        const names = new Set([name, "shop"]);
        h.rows.forEach((x) => names.add(x.from === name ? x.to : x.from));
        const pr = await q("select name, avatar_v, phone, show_phone from users where name = any($1)", [[...names]]);
        const profiles = {};
        pr.rows.forEach((x) => { profiles[x.name] = { av: x.avatar_v, phone: x.show_phone || x.name === name ? x.phone : null }; });
        const msgs = h.rows.reverse().map((x) => ({
          id: Number(x.id), from: x.from, to: x.to, text: x.text, kind: x.kind, at: x.at,
          st: x.read_at ? "read" : x.delivered_at ? "delivered" : "sent",
          file: x.fid ? { id: Number(x.fid), name: x.fname, mime: x.fmime, size: x.fsize } : null,
        }));
        return send({ type: "history", msgs, unread, profiles });
      }
      if (!name) return fail("Join first");

      if (m.type === "read") {
        const other = String(m.with || "").toLowerCase();
        const r = await q("update messages set read_at=now(), delivered_at=coalesce(delivered_at, now()) where to_user=$1 and from_user=$2 and read_at is null returning id", [name, other]);
        await q("insert into reads(name,other,last_id) select $1,$2,coalesce(max(id),0) from messages where to_user=$1 and from_user=$2 on conflict (name,other) do update set last_id = excluded.last_id", [name, other]);
        const u = online.get(other);
        if (r.rows.length && u && u.ws.readyState === 1) u.ws.send(JSON.stringify({ type: "receipt", by: name, status: "read", ids: r.rows.map((x) => Number(x.id)) }));
        return;
      }

      if (m.type === "lowdata") { online.get(name).lowData = !!m.on; return; }

      if (m.type === "msg") {
        const text = String(m.text || "").slice(0, 2000);
        const to = String(m.to || "").toLowerCase();
        if (!to || !text) return;
        if (to === name) return fail("You cannot message yourself");
        const ex = await q("select 1 from users where name=$1", [to]);
        if (!ex.rows.length) return fail("No user called " + to);
        const d = await deliver(name, to, text, "msg", null, null);
        return send({ type: "sent", cid: m.cid, id: d.id, to, text, kind: "msg", file: null, at: d.at, st: d.st });
      }

      if (m.type === "typing") {
        const u = online.get(String(m.to || "").toLowerCase());
        if (u && !u.lowData && u.ws.readyState === 1) u.ws.send(JSON.stringify({ type: "typing", from: name })); // skipped in low-data mode
        return;
      }

      if (m.type === "catalog") return send({ type: "catalog", products });

      if (m.type === "order") {
        let total = 0;
        const lines = [];
        for (const it of m.items || []) {
          const p = products.find((x) => x.id === it.id);
          const qty = Math.min(Math.max(parseInt(it.qty) || 0, 0), p ? p.stock : 0);
          if (p && qty > 0) { total += p.price * qty; lines.push(qty + " x " + p.name); }
        }
        if (!lines.length) return fail("Nothing to order");
        const n = (await q("select nextval('order_seq') as n")).rows[0].n;
        const text = "Order #" + n + ": " + lines.join(", ") + ". Total TSh " + total.toLocaleString("en-US");
        const o1 = await deliver(name, "shop", text, "order", null, null);
        send({ type: "sent", id: o1.id, to: "shop", text, kind: "order", file: null, at: o1.at, st: o1.st });
        await deliver("shop", name, "We got your " + text, "order", null, null);
      }
    } catch (e) {
      console.error(e);
      fail("Something went wrong. Try again.");
    }
  });

  ws.on("close", () => {
    if (name && online.get(name) && online.get(name).ws === ws) online.delete(name);
  });
});

setup()
  .then(() => server.listen(PORT, () => console.log("Gumzo server running on http://localhost:" + PORT)))
  .catch((e) => { console.error("Database setup failed:", e.message); process.exit(1); });
