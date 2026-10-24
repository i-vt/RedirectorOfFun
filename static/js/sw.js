/* Service worker: display Web Push notifications for the control plane. */
self.addEventListener("push", (event) => {
  let payload = {title: "Control plane notification", body: "", url: "/panel/submissions/"};
  try {
    if (event.data) payload = Object.assign(payload, event.data.json());
  } catch { /* keep defaults on malformed payloads */ }
  event.waitUntil(self.registration.showNotification(payload.title, {
    body: payload.body,
    icon: "/static/favicon.svg",
    badge: "/static/favicon.svg",
    data: {url: payload.url},
    tag: "rdr-webpush",
  }));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || "/panel/";
  event.waitUntil(clients.matchAll({type: "window", includeUncontrolled: true}).then((list) => {
    for (const client of list) {
      if ("focus" in client) return client.focus();
    }
    return clients.openWindow(url);
  }));
});
