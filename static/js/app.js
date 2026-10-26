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

  // Styled confirm dialogs: every data-confirm form gets a themed modal
  // instead of a native popup, with a per-message "don't ask again" memory.
  const NO_CONFIRM_KEY = "rdr-no-confirm";
  const noConfirmList = () => {
    try { return JSON.parse(localStorage.getItem(NO_CONFIRM_KEY) || "[]"); } catch { return []; }
  };
  const isNoConfirm = (message) => noConfirmList().includes(message);
  const rememberNoConfirm = (message) => {
    const list = noConfirmList();
    if (!list.includes(message)) {
      list.push(message);
      localStorage.setItem(NO_CONFIRM_KEY, JSON.stringify(list));
    }
  };
  window.clearNoConfirm = () => localStorage.removeItem(NO_CONFIRM_KEY);

  let confirmOverlay = null;
  function ensureConfirmOverlay() {
    if (confirmOverlay) return confirmOverlay;
    const style = document.createElement("style");
    style.textContent = `
      .confirm-overlay{position:fixed;inset:0;background:rgba(4,8,14,.72);z-index:400;display:flex;align-items:center;justify-content:center;padding:18px}
      .confirm-overlay[hidden]{display:none}
      .confirm-card{background:var(--s-surface,var(--surface,#161b22));border:var(--c-panel-border,1px solid var(--border,#30363d));border-radius:10px;padding:22px;max-width:420px;width:100%;color:var(--s-text,var(--text,#e6edf3));font-family:inherit}
      .confirm-card .confirm-title{font-size:.62rem;letter-spacing:.16em;color:var(--s-accent,var(--accent,#3fb68b));margin-bottom:10px}
      .confirm-card p{margin:0 0 14px;font-size:.85rem;line-height:1.5}
      .confirm-card label{display:flex;align-items:center;gap:8px;font-size:.72rem;color:var(--s-muted,var(--muted,#8b949e));margin-bottom:14px}
      .confirm-card .confirm-actions{display:flex;gap:10px;justify-content:flex-end}
      .confirm-card .confirm-actions button{min-height:40px;padding:8px 18px;border-radius:6px;border:1px solid var(--s-border,var(--border,#30363d));background:transparent;color:var(--s-text,var(--text,#e6edf3));font:inherit;cursor:pointer}
      .confirm-card .confirm-actions .confirm-yes{background:var(--c-button-bg,var(--accent,#3fb68b));color:var(--c-button-text,#04140d);border-color:transparent;font-weight:600}
      @media (max-width:600px){.confirm-card{max-width:100%;padding:16px}.confirm-card .confirm-actions button{flex:1;min-height:48px}}
    `;
    document.head.appendChild(style);
    const overlay = document.createElement("div");
    overlay.className = "confirm-overlay";
    overlay.hidden = true;
    overlay.innerHTML = `
      <div class="confirm-card" role="alertdialog" aria-modal="true">
        <div class="confirm-title">CONFIRM ACTION</div>
        <p class="confirm-message"></p>
        <label><input type="checkbox" class="confirm-skip"> Don't ask me again for this action</label>
        <div class="confirm-actions">
          <button type="button" class="confirm-no">Cancel</button>
          <button type="button" class="confirm-yes">Confirm</button>
        </div>
      </div>`;
    document.body.appendChild(overlay);
    confirmOverlay = overlay;
    return overlay;
  }

  document.addEventListener("submit", (event) => {
    const form = event.target;
    const message = form.dataset && form.dataset.confirm;
    if (!message) return;
    if (form.dataset.confirmed === "1") {
      delete form.dataset.confirmed;
      return;
    }
    if (isNoConfirm(message)) return;
    event.preventDefault();
    const overlay = ensureConfirmOverlay();
    overlay.querySelector(".confirm-message").textContent = message;
    const skip = overlay.querySelector(".confirm-skip");
    skip.checked = false;
    overlay.hidden = false;
    const no = overlay.querySelector(".confirm-no");
    const yes = overlay.querySelector(".confirm-yes");
    const cleanup = () => { overlay.hidden = true; no.onclick = yes.onclick = overlay.onclick = null; };
    no.onclick = () => cleanup();
    overlay.onclick = (e) => { if (e.target === overlay) cleanup(); };
    yes.onclick = () => {
      if (skip.checked) rememberNoConfirm(message);
      cleanup();
      form.dataset.confirmed = "1";
      form.requestSubmit();
    };
    yes.focus();
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
    function musicBoxNote(ctx, frequency, delay) {
      for (const [partial, level] of [[1, 0.5], [2, 0.18], [4, 0.05]]) {
        const oscillator = ctx.createOscillator();
        const gain = ctx.createGain();
        oscillator.type = "sine";
        oscillator.frequency.setValueAtTime(frequency * partial, ctx.currentTime + delay);
        const at = ctx.currentTime + delay;
        gain.gain.setValueAtTime(0.1 * level, at);
        gain.gain.exponentialRampToValueAtTime(0.0001, at + 0.9);
        oscillator.connect(gain).connect(ctx.destination);
        oscillator.start(at);
        oscillator.stop(at + 1);
      }
    }

    function bing() {
      if (!soundEnabled()) return;
      try {
        audioContext = audioContext || new (window.AudioContext || window.webkitAudioContext)();
        if (document.body.classList.contains("theme-obnoxious")) {
          // A descending music-box motif: two notes, one step and a half down.
          musicBoxNote(audioContext, 880, 0);
          musicBoxNote(audioContext, 587.33, 0.16);
          return;
        }
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

  // Count-up animation for metric/stat numbers (progressive enhancement:
  // the real value is already rendered, we just rewind and animate it).
  const counters = document.querySelectorAll("[data-count]");
  if (counters.length && matchMedia("(prefers-reduced-motion: no-preference)").matches) {
    const animate = (el) => {
      const target = parseInt(el.dataset.count, 10);
      if (Number.isNaN(target)) return;
      const start = performance.now(), duration = 650;
      const step = (now) => {
        const t = Math.min((now - start) / duration, 1);
        el.textContent = String(Math.round(target * (1 - Math.pow(1 - t, 3))));
        if (t < 1) requestAnimationFrame(step);
      };
      requestAnimationFrame(step);
    };
    const observer = new IntersectionObserver((entries) => {
      for (const entry of entries) {
        if (entry.isIntersecting) { animate(entry.target); observer.unobserve(entry.target); }
      }
    }, {threshold: .4});
    counters.forEach(el => observer.observe(el));
  }
})();

// ─── Inline help: tooltips on touch, per-page guide modal ──────────────────
(() => {
  // Tooltips: hover works on desktop; tap toggles on touch devices.
  document.addEventListener("click", (event) => {
    const dot = event.target.closest("[data-tip]");
    document.querySelectorAll("[data-tip].tip-open").forEach((el) => {
      if (el !== dot) el.classList.remove("tip-open");
    });
    if (dot) dot.classList.toggle("tip-open");
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      document.querySelectorAll("[data-tip].tip-open").forEach((el) => el.classList.remove("tip-open"));
    }
  });

  // Per-page guide: the ? button opens a modal with the page's guide block.
  const openBtn = document.getElementById("guide-open");
  const modal = document.getElementById("guide-modal");
  if (!openBtn || !modal) return;
  const body = modal.querySelector(".guide-body");
  if (body && body.textContent.trim()) openBtn.hidden = false;
  const close = () => { modal.hidden = true; };
  openBtn.addEventListener("click", () => { modal.hidden = false; });
  modal.addEventListener("click", (event) => { if (event.target === modal) close(); });
  const closeBtn = modal.querySelector("#guide-close");
  if (closeBtn) closeBtn.addEventListener("click", close);
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !modal.hidden) close();
    if (event.key === "?" && event.shiftKey && !/INPUT|TEXTAREA|SELECT/.test(event.target.tagName)) {
      if (!openBtn.hidden) { event.preventDefault(); modal.hidden = false; }
    }
  });
})();

// ─── Live regions: auto-refresh without a page reload ──────────────────────
// <div id="x" data-autorefresh="5"> re-fetches the page every N seconds and
// swaps its content when it changed. Focused form fields inside survive.
(() => {
  document.querySelectorAll("[data-autorefresh]").forEach((el) => {
    const seconds = parseInt(el.dataset.autorefresh, 10);
    if (!seconds || seconds < 2) return;
    setInterval(async () => {
      if (el.querySelector("input:focus, textarea:focus, select:focus")) return;
      try {
        const response = await fetch(location.href);
        const html = await response.text();
        const fresh = new DOMParser().parseFromString(html, "text/html").getElementById(el.id);
        if (fresh && fresh.innerHTML !== el.innerHTML) el.innerHTML = fresh.innerHTML;
      } catch { /* offline hiccup: retry next tick */ }
    }, seconds * 1000);
  });
})();
