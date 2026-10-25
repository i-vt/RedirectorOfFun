(() => {
  // Code editing comforts for the lure/decoy browser editors:
  // Tab inserts spaces, Ctrl/Cmd+S saves the closest form.
  document.querySelectorAll("textarea[data-code]").forEach((area) => {
    area.addEventListener("keydown", (event) => {
      if (event.key === "Tab") {
        event.preventDefault();
        const start = area.selectionStart;
        const end = area.selectionEnd;
        area.value = area.value.slice(0, start) + "  " + area.value.slice(end);
        area.selectionStart = area.selectionEnd = start + 2;
      }
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "s") {
        event.preventDefault();
        const form = area.closest("form");
        if (form) form.requestSubmit();
      }
    });
  });
})();
