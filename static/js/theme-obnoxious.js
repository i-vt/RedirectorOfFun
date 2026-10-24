/* Obnoxious Clown interactive layer: flashlight cursor, button nod, and the
   clown vocabulary for the sidebar. Loaded only when the theme is active. */
(() => {
  "use strict";
  if (matchMedia("(prefers-reduced-motion: reduce)").matches) return;

  // Flashlight cursor: a faint spotlight following the pointer.
  const spot = document.createElement("div");
  spot.id = "circus-flashlight";
  document.body.appendChild(spot);
  document.addEventListener("mousemove", (event) => {
    spot.style.left = event.clientX + "px";
    spot.style.top = event.clientY + "px";
  }, { passive: true });

  // Nodding-clown wobble on every button press.
  document.addEventListener("click", (event) => {
    const button = event.target.closest(".button");
    if (!button) return;
    button.classList.remove("wobble");
    void button.offsetWidth;
    button.classList.add("wobble");
    button.addEventListener("animationend", () => button.classList.remove("wobble"), { once: true });
  });

  // Clown vocabulary: rename the navigation labels only in this theme.
  const vocabulary = {
    "WORKSPACE": "THE RING",
    "ADMINISTRATION": "BACKSTAGE",
    "Overview": "CENTER RING",
    "404 Events": "LOST SOULS",
    "Delivery Links": "THE ACTS",
    "Approvals": "THE AUDIENCE",
    "Operators": "THE TROUPE",
    "Banned IPs": "THROWN OUT",
    "Blocking Rules": "BOUNCERS",
    "Agent Channels": "PUPPETS",
    "Gate Events": "SIDESHOW",
    "Decoy Pages": "MASKS",
    "Audit Log": "MEMOIRS",
    "Settings": "DRESSING ROOM",
    "Security": "THE CAGE",
    "Service Health": "THE PULSE",
    "Self-Test": "REHEARSAL",
    "Mobile UI": "POCKET SHOW",
    "[ SIGN OUT ]": "[ LEAVE THE TENT ]",
  };
  const swap = (el) => {
    for (const node of el.childNodes) {
      if (node.nodeType === Node.TEXT_NODE && vocabulary[node.textContent.trim()]) {
        node.textContent = node.textContent.replace(node.textContent.trim(), vocabulary[node.textContent.trim()]);
      }
    }
  };
  document.querySelectorAll(".sidebar .nav-label, .sidebar .primary-nav a, .sidebar .text-button").forEach(swap);
})();
