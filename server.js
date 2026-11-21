// Gumzo server: accounts with passwords, saved messages (Postgres), translation, low-data mode, shop orders.
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

// Shop catalog (edit these to match your real products)
const products = [
  { id: 1, name: "Bluetooth speaker", price: 45000, stock: 12 },
  { id: 2, name: "Phone charger 20W", price: 15000, stock: 40 },
  { id: 3, name: "Wireless earbuds", price: 60000, stock: 8 },
];

const online = new Map(); // name -> { ws, lowData }
const cache = new Map();  // translation cache
const fails = new Map();  // ip -> times of wrong passwords

function json(res, code, data) {
  res.writeHead(code, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
  res.end(JSON.stringify(data));
}
function readBody(req) {
  return new Promise((resolve) => {
    let b = "";
    req.on("data", (c) => { b += c; if (b.length > 5000) req.destroy(); });
    req.on("end", () => { try { resolve(JSON.parse(b)); } catch { resolve({}); } });
  });
}

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

async function setup() {
  await q("create table if not exists users(name text primary key, hash text not null, created timestamptz default now())");
  await q("create table if not exists sessions(token text primary key, name text not null, created timestamptz default now())");
  await q("create table if not exists messages(id bigserial primary key, from_user text not null, to_user text not null, text text not null, kind text not null default 'msg', created timestamptz default now())");
  await q("create index if not exists msg_from on messages(from_user)");
  await q("create index if not exists msg_to on messages(to_user)");
  await q("create sequence if not exists order_seq");
  // The shop account is created from the SHOP_PASSWORD you set in Render. Nobody can sign up as "shop".
  if (process.env.SHOP_PASSWORD) {
    await q("insert into users(name,hash) values('shop',$1) on conflict (name) do update set hash = excluded.hash", [hash(process.env.SHOP_PASSWORD)]);
  }
}

const files = {
  "/": ["index.html", "text/html; charset=utf-8"],
  "/manifest.json": ["manifest.json", "application/manifest+json"],
  "/sw.js": ["sw.js", "text/javascript"],
  "/icon-192.png": ["icon-192.png", "image/png"],
  "/icon-512.png": ["icon-512.png", "image/png"],
};

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");
  if (files[url.pathname]) {
    res.writeHead(200, { "Content-Type": files[url.pathname][1] });
    return res.end(fs.readFileSync(path.join(__dirname, files[url.pathname][0])));
  }
  if (url.pathname === "/api/products") return json(res, 200, products);

  // ---------- Accounts ----------
  if (req.method === "POST" && (url.pathname === "/api/register" || url.pathname === "/api/login")) {
    const ip = String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
    if (tooMany(ip)) return json(res, 429, { error: "Too many wrong tries. Wait 15 minutes." });
    const b = await readBody(req);
    const name = String(b.name || "").trim().toLowerCase();
    const pw = String(b.password || "");
    try {
      if (url.pathname === "/api/register") {
        if (!/^[a-z0-9_]{3,20}$/.test(name)) return json(res, 400, { error: "Name: 3 to 20 letters, numbers or _" });
        if (name === "shop") return json(res, 400, { error: "That name is reserved" });
        if (pw.length < 6) return json(res, 400, { error: "Password needs at least 6 characters" });
        const r = await q("insert into users(name,hash) values($1,$2) on conflict do nothing returning name", [name, hash(pw)]);
        if (!r.rows.length) return json(res, 409, { error: "That name is taken. Try another." });
      } else {
        const r = await q("select hash from users where name=$1", [name]);
        if (!r.rows.length || !check(pw, r.rows[0].hash)) { noteFail(ip); return json(res, 401, { error: "Wrong name or password" }); }
      }
      const token = crypto.randomBytes(32).toString("hex");
      await q("insert into sessions(token,name) values($1,$2)", [token, name]);
      return json(res, 200, { token, name });
    } catch (e) {
      console.error(e);
      return json(res, 500, { error: "Server problem. Try again in a moment." });
    }
  }
  if (req.method === "POST" && url.pathname === "/api/logout") {
    const b = await readBody(req);
    try { await q("delete from sessions where token=$1", [String(b.token || "")]); } catch (e) {}
    return json(res, 200, { ok: true });
  }

  // ---------- Translation ----------
  if (url.pathname === "/api/translate") {
    const text = (url.searchParams.get("text") || "").slice(0, 500);
    const from = url.searchParams.get("from") || "en";
    const to = url.searchParams.get("to") || "sw";
    if (!text) return json(res, 400, { error: "text is required" });
    const key = from + "|" + to + "|" + text;
    if (cache.has(key)) return json(res, 200, { text: cache.get(key), cached: true });
    try {
      const api = "https://api.mymemory.translated.net/get?q=" + encodeURIComponent(text) + "&langpair=" + from + "|" + to;
      const data = await (await fetch(api)).json();
      const out = data.responseData.translatedText;
      cache.set(key, out);
      return json(res, 200, { text: out });
    } catch (e) {
      return json(res, 502, { error: "Translation is unavailable right now. Try again." });
    }
  }
  json(res, 404, { error: "not found" });
});

// ---------- Chat (WebSocket) ----------
const wss = new WebSocketServer({ server, perMessageDeflate: true });

function push(user, msg) {
  if (user.ws.readyState !== 1) return;
  const out = user.lowData ? { t: msg.type, f: msg.from, x: msg.text, id: msg.id } : msg; // low-data: short keys
  user.ws.send(JSON.stringify(out));
}

wss.on("connection", (ws) => {
  let name = null;
  const fail = (text) => ws.send(JSON.stringify({ type: "error", text }));

  ws.on("message", async (raw) => {
    try {
      let m;
      try { m = JSON.parse(raw); } catch { return; }

      if (m.type === "join") {
        const r = await q("select name from sessions where token=$1", [String(m.token || "")]);
        if (!r.rows.length) return ws.send(JSON.stringify({ type: "auth" }));
        name = r.rows[0].name;
        online.set(name, { ws, lowData: !!m.lowData });
        ws.send(JSON.stringify({ type: "joined", name }));
        const h = await q('select from_user as "from", to_user as "to", text, created as at from messages where from_user=$1 or to_user=$1 order by id desc limit 300', [name]);
        return ws.send(JSON.stringify({ type: "history", msgs: h.rows.reverse() }));
      }
      if (!name) return fail("Join first");

      if (m.type === "lowdata") { online.get(name).lowData = !!m.on; return; }

      if (m.type === "msg") {
        const text = String(m.text || "").slice(0, 2000);
        const to = String(m.to || "").toLowerCase();
        if (!to || !text) return;
        const ex = await q("select 1 from users where name=$1", [to]);
        if (!ex.rows.length) return fail("No user called " + to);
        await q("insert into messages(from_user,to_user,text) values($1,$2,$3)", [name, to, text]);
        const u = online.get(to);
        if (u) push(u, { type: "msg", from: name, text, id: Date.now() });
        return;
      }

      if (m.type === "typing") {
        const u = online.get(String(m.to || "").toLowerCase());
        if (u && !u.lowData) push(u, { type: "typing", from: name }); // skipped in low-data mode
        return;
      }

      if (m.type === "catalog") return ws.send(JSON.stringify({ type: "catalog", products }));

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
        const reply = "We got your " + text;
        await q("insert into messages(from_user,to_user,text,kind) values($1,'shop',$2,'order'),('shop',$1,$3,'order')", [name, text, reply]);
        const s = online.get("shop");
        if (s) push(s, { type: "order", from: name, text, total, id: n });
        push(online.get(name), { type: "order", from: "shop", text: reply, total, id: n });
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
