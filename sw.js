// Gumzo service worker: always tries the network first so new versions show up, falls back to the saved copy when offline.
const V = "gumzo-v3";
self.addEventListener("install", (e) => {
  self.skipWaiting();
  e.waitUntil(caches.open(V).then((c) => c.addAll(["/", "/manifest.json", "/icon-192.png"])).catch(() => {}));
});
self.addEventListener("activate", (e) => {
  e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== V).map((k) => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener("fetch", (e) => {
  const u = new URL(e.request.url);
  if (e.request.method !== "GET" || u.origin !== location.origin || u.pathname.startsWith("/api/") || u.pathname.startsWith("/avatar/")) return;
  e.respondWith(
    fetch(e.request)
      .then((r) => { if (r.ok) { const c = r.clone(); caches.open(V).then((x) => x.put(e.request, c)); } return r; })
      .catch(() => caches.match(e.request).then((r) => r || caches.match("/")))
  );
});
