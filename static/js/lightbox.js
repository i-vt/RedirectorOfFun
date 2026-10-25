(() => {
  // Shared lightbox: any <img data-lightbox> opens full-size in an overlay.
  // data-full overrides the full-size URL, data-caption sets the caption.
  const overlay = document.createElement("div");
  overlay.className = "lightbox-overlay";
  overlay.hidden = true;
  overlay.innerHTML = '<img alt=""><div class="lightbox-caption mono"></div>';
  const fullImg = overlay.querySelector("img");
  const caption = overlay.querySelector(".lightbox-caption");
  const close = () => { overlay.hidden = true; };
  document.addEventListener("click", (event) => {
    const thumb = event.target.closest("img[data-lightbox]");
    if (thumb) {
      event.preventDefault();
      fullImg.src = thumb.dataset.full || thumb.src;
      caption.textContent = thumb.dataset.caption || thumb.alt || "";
      overlay.hidden = false;
      return;
    }
    if (!overlay.hidden && overlay.contains(event.target)) close();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !overlay.hidden) close();
  });
  if (document.body) document.body.appendChild(overlay);
  else document.addEventListener("DOMContentLoaded", () => document.body.appendChild(overlay));
})();
