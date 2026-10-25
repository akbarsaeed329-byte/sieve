// Sieve service worker: push notifications only. No caching of security data.
self.addEventListener('push', (e) => {
  let d = {}; try { d = e.data.json(); } catch { d = { title: 'Sieve', body: e.data && e.data.text() }; }
  e.waitUntil(self.registration.showNotification(d.title || 'Sieve', { body: d.body || '', tag: d.tag, data: { url: d.url || '/' }, icon: '/favicon.svg' }));
});
self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  const url = new URL((e.notification.data && e.notification.data.url) || '/', self.location.origin);
  if (url.origin !== self.location.origin) return;   // only ever open Sieve itself
  e.waitUntil(clients.matchAll({ type: 'window' }).then((ws) => {
    for (const w of ws) if (w.url.startsWith(self.location.origin)) { w.navigate(url.href); return w.focus(); }
    return clients.openWindow(url.href);
  }));
});
