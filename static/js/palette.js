(() => {
  // Command palette: Ctrl+K (or /) jumps anywhere. Data comes from the
  // #palette-data json script in base.html.
  const source = document.getElementById("palette-data");
  const overlay = document.getElementById("palette-modal");
  if (!source || !overlay) return;
  const items = JSON.parse(source.textContent);
  const input = document.getElementById("palette-input");
  const list = document.getElementById("palette-list");
  let active = 0;
  let visible = [];

  const open = () => { overlay.hidden = false; input.value = ""; render(""); input.focus(); };
  const close = () => { overlay.hidden = true; };

  function render(query) {
    const q = query.trim().toLowerCase();
    visible = items.filter((item) => item.label.toLowerCase().includes(q));
    active = 0;
    let group = "";
    const rows = [];
    visible.slice(0, 40).forEach((item, index) => {
      if (item.group !== group) {
        group = item.group;
        rows.push(`<div class="palette-group">${group}</div>`);
      }
      rows.push(`<a class="palette-item${index === active ? " active" : ""}" data-index="${index}" href="${item.url}">${item.label}<span class="kbd-hint">${item.hint || ""}</span></a>`);
    });
    list.innerHTML = rows.join("") || '<div class="palette-group">Nothing matches.</div>';
  }

  function step(delta) {
    if (!visible.length) return;
    active = (active + delta + visible.length) % Math.min(visible.length, 40);
    list.querySelectorAll(".palette-item").forEach((el) => {
      el.classList.toggle("active", parseInt(el.dataset.index, 10) === active);
    });
    list.querySelector(".palette-item.active")?.scrollIntoView({block: "nearest"});
  }

  input.addEventListener("input", () => render(input.value));
  input.addEventListener("keydown", (event) => {
    if (event.key === "ArrowDown") { event.preventDefault(); step(1); }
    if (event.key === "ArrowUp") { event.preventDefault(); step(-1); }
    if (event.key === "Enter" && visible[active]) { window.location.href = visible[active].url; }
  });
  list.addEventListener("click", (event) => event.target.closest(".palette-item") && close());
  overlay.addEventListener("click", (event) => { if (event.target === overlay) close(); });
  document.addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      overlay.hidden ? open() : close();
      return;
    }
    if (event.key === "/" && !/INPUT|TEXTAREA|SELECT/.test(event.target.tagName)) {
      event.preventDefault();
      open();
      return;
    }
    if (event.key === "Escape" && !overlay.hidden) close();
  });
})();
