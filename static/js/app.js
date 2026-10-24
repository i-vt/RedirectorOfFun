(() => {
  "use strict";
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

  function updateClock() {
    const clock = $("#utc-clock");
    if (clock) clock.textContent = new Intl.DateTimeFormat("en-GB", {
      timeZone: "UTC", hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
    }).format(new Date()) + " UTC";
  }
  updateClock();
  setInterval(updateClock, 1000);

  document.addEventListener("click", async (event) => {
    const close = event.target.closest(".toast-close");
    if (close) close.closest(".toast")?.remove();
    const copy = event.target.closest("[data-copy]");
    if (copy) {
      const input = $(copy.dataset.copy);
      if (!input) return;
      try {
        await navigator.clipboard.writeText(input.value);
        const previous = copy.textContent;
        copy.textContent = "Copied";
        setTimeout(() => { copy.textContent = previous; }, 1500);
      } catch {
        input.select();
        document.execCommand("copy");
      }
    }
  });

  document.addEventListener("submit", (event) => {
    const message = event.target.dataset.confirm;
    if (message && !window.confirm(message)) event.preventDefault();
  });

  document.addEventListener("htmx:configRequest", (event) => {
    if (event.detail.verb !== "get") {
      event.detail.headers["X-CSRFToken"] = $('meta[name="csrf-token"]')?.content || "";
    }
  });

  function toast(title, detail) {
    const region = $("#toast-region");
    if (!region) return;
    const node = document.createElement("div");
    node.className = "toast";
    const text = document.createElement("span");
    const strong = document.createElement("strong");
    strong.textContent = title;
    text.append(strong, document.createElement("br"), document.createTextNode(detail || ""));
    const button = document.createElement("button");
    button.type = "button";
    button.className = "toast-close";
    button.setAttribute("aria-label", "Dismiss notification");
    button.textContent = "×";
    button.addEventListener("click", () => node.remove());
    node.append(text, button);
    region.append(node);
    setTimeout(() => node.remove(), 8000);
  }

  const permissionButton = $("#browser-permission");
  const permissionState = $("#browser-permission-state");
  function updatePermissionState() {
    if (!permissionState) return;
    if (!("Notification" in window)) permissionState.textContent = "Browser notifications are not supported.";
    else permissionState.textContent = `Browser permission: ${Notification.permission}.`;
  }
  updatePermissionState();
  permissionButton?.addEventListener("click", async () => {
    if (!("Notification" in window)) return;
    await Notification.requestPermission();
    updatePermissionState();
  });

  if (document.body.dataset.authenticated === "true") {
    let lastId = 0;
    let initialized = false;
    const soundEnabled = () => localStorage.getItem("rdr-sound") !== "off";
    let audioContext = null;
    function bing() {
      if (!soundEnabled()) return;
      try {
        audioContext = audioContext || new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = audioContext.createOscillator();
        const gain = audioContext.createGain();
        oscillator.type = "sine";
        oscillator.frequency.setValueAtTime(880, audioContext.currentTime);
        oscillator.frequency.exponentialRampToValueAtTime(1320, audioContext.currentTime + 0.08);
        gain.gain.setValueAtTime(0.12, audioContext.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.0001, audioContext.currentTime + 0.5);
        oscillator.connect(gain).connect(audioContext.destination);
        oscillator.start();
        oscillator.stop(audioContext.currentTime + 0.55);
      } catch { /* Audio is best-effort. */ }
    }
    const soundToggle = $("#sound-toggle");
    const syncSoundToggle = () => { if (soundToggle) soundToggle.textContent = soundEnabled() ? "SOUND: ON" : "SOUND: OFF"; };
    soundToggle?.addEventListener("click", () => {
      localStorage.setItem("rdr-sound", soundEnabled() ? "off" : "on");
      syncSoundToggle();
      if (soundEnabled()) bing();
    });
    syncSoundToggle();
    async function pollNotifications() {
      try {
        const response = await fetch(`/api/v1/notifications/recent/?after=${lastId}`, {headers: {"Accept": "application/json"}});
        if (!response.ok) return;
        const data = await response.json();
        const entries = Array.isArray(data) ? data : data.results || [];
        for (const item of entries) {
          lastId = Math.max(lastId, item.id);
          if (initialized) {
            const title = item.payload.title || "Control plane notification";
            const detail = item.payload.detail || "";
            toast(title, detail);
            bing();
            if (item.channel === "browser" && "Notification" in window && Notification.permission === "granted") {
              new Notification(title, {body: detail, tag: `rdr-notification-${item.id}`});
            }
          }
        }
        initialized = true;
      } catch { /* A transient poll failure must not interrupt the panel. */ }
    }
    pollNotifications();
    setInterval(pollNotifications, 15000);
  }
})();
