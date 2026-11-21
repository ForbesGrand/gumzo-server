// Gumzo server: relays chat messages, translates text, supports low-data mode, takes shop orders.
const http = require("http");
const { WebSocketServer } = require("ws");

const PORT = process.env.PORT || 3000;

// Shop catalog (edit these to match your real products)
const products = [
  { id: 1, name: "Bluetooth speaker", price: 45000, stock: 12 },
  { id: 2, name: "Phone charger 20W", price: 15000, stock: 40 },
  { id: 3, name: "Wireless earbuds", price: 60000, stock: 8 },
];

const online = new Map(); // name -> { ws, lowData }
const inbox = new Map();  // name -> messages waiting for someone who is offline
const orders = [];
const cache = new Map(); // saves data and time: same translation is only fetched once

function json(res, code, data) {
  res.writeHead(code, { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" });
  res.end(JSON.stringify(data));
}

// ---------- 1. Translation (plain web address, works for any language pair) ----------
// Example: /api/translate?text=Habari&from=sw&to=en
const fs = require("fs");
const path = require("path");

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");
  if (url.pathname === "/") {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    return res.end(fs.readFileSync(path.join(__dirname, "index.html")));
  }
  if (url.pathname === "/api/products") return json(res, 200, products);
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
const wss = new WebSocketServer({ server, perMessageDeflate: true }); // deflate = smaller messages

// ---------- 3. Low-data mode: short keys, no typing signals ----------
function push(user, msg) {
  if (user.ws.readyState !== 1) return;
  const out = user.lowData ? { t: msg.type, f: msg.from, x: msg.text, id: msg.id } : msg;
  user.ws.send(JSON.stringify(out));
}

function deliver(to, msg) {
  const user = online.get(to);
  if (user) return push(user, msg);
  if (!inbox.has(to)) inbox.set(to, []);
  inbox.get(to).push(msg);
}

wss.on("connection", (ws) => {
  let name = null;
  const fail = (text) => ws.send(JSON.stringify({ type: "error", text }));

  ws.on("message", (raw) => {
    let m;
    try { m = JSON.parse(raw); } catch { return; }

    if (m.type === "join") {
      name = String(m.name || "").trim().slice(0, 30);
      if (!name) return fail("Name is required");
      online.set(name, { ws, lowData: !!m.lowData });
      ws.send(JSON.stringify({ type: "joined", name }));
      for (const msg of inbox.get(name) || []) push(online.get(name), msg);
      inbox.delete(name);
      return;
    }
    if (!name) return fail("Join first");

    if (m.type === "lowdata") { online.get(name).lowData = !!m.on; return; }

    if (m.type === "msg") {
      const text = String(m.text || "").slice(0, 2000);
      if (!m.to || !text) return;
      return deliver(m.to, { type: "msg", from: name, text, id: Date.now() });
    }

    if (m.type === "typing") {
      const u = online.get(m.to);
      if (u && !u.lowData) push(u, { type: "typing", from: name }); // skipped to save data
      return;
    }

    if (m.type === "catalog") return ws.send(JSON.stringify({ type: "catalog", products }));

    // ---------- 2. Shop chat: place an order inside the conversation ----------
    // Client sends: { type: "order", items: [{ id: 1, qty: 2 }] }
    if (m.type === "order") {
      let total = 0;
      const lines = [];
      for (const it of m.items || []) {
        const p = products.find((x) => x.id === it.id);
        const qty = Math.min(Math.max(parseInt(it.qty) || 0, 0), p ? p.stock : 0);
        if (p && qty > 0) { total += p.price * qty; lines.push(qty + " x " + p.name); }
      }
      if (!lines.length) return fail("Nothing to order");
      const order = { id: orders.length + 1, from: name, lines, total };
      orders.push(order);
      const text = "Order #" + order.id + ": " + lines.join(", ") + ". Total TSh " + total.toLocaleString("en-US");
      deliver("shop", { type: "order", from: name, text, total, id: order.id });
      deliver(name, { type: "order", from: "shop", text: "We got your " + text, total, id: order.id });
    }
  });

  ws.on("close", () => {
    if (name && online.get(name) && online.get(name).ws === ws) online.delete(name);
  });
});

server.listen(PORT, () => console.log("Gumzo server running on http://localhost:" + PORT));
