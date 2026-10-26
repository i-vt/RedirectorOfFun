(() => {
  // Progressive disclosure for mutually exclusive options:
  //   <label data-show-when="gate_type:token">…</label>     shown only when the
  //   named control's value matches (pipe for several: "kind:file|proxy").
  //   data-also-when="cipher:aes256"                        second condition (AND).
  //   data-dim-when="kind:file"                             greyed + inert unless the
  //                                                         named control matches.
  // Excluded fields stay submitted (values survive an accidental toggle), they
  // are simply out of the way until the compatible option is selected.
  const currentValue = (control) => {
    if (control.type === "checkbox") return control.checked ? "on" : "off";
    return control.value;
  };
  const matches = (el, spec) => {
    const idx = spec.indexOf(":");
    if (idx === -1) return true;
    const control = el.closest("form")?.querySelector(`[name="${spec.slice(0, idx)}"]`)
      || document.querySelector(`[name="${spec.slice(0, idx)}"]`);
    if (!control) return true;
    return spec.slice(idx + 1).split("|").includes(currentValue(control));
  };
  const refresh = () => {
    document.querySelectorAll("[data-show-when]").forEach((el) => {
      const show = matches(el, el.dataset.showWhen)
        && (!el.dataset.alsoWhen || matches(el, el.dataset.alsoWhen));
      el.classList.toggle("field-hidden", !show);
    });
    document.querySelectorAll("[data-dim-when]").forEach((el) => {
      const dim = !matches(el, el.dataset.dimWhen);
      el.classList.toggle("field-dimmed", dim);
      el.inert = dim;
    });
    document.querySelectorAll("[data-feature-when]").forEach((el) => {
      el.classList.toggle("field-featured", matches(el, el.dataset.featureWhen));
    });
    // Auto-open advanced <details> when their trigger matches (e.g. picking the
    // network gate opens the NETWORK PROFILE section). Manual toggles win: we
    // only close what we auto-opened.
    document.querySelectorAll("details[data-autoopen-when]").forEach((el) => {
      if (matches(el, el.dataset.autoopenWhen)) {
        el.open = true;
        el.dataset.autoopened = "1";
      } else if (el.dataset.autoopened) {
        el.open = false;
        delete el.dataset.autoopened;
      }
    });
    // Auto-check boxes while their trigger matches, until the operator touches
    // them manually (network gate defaults operator admission to ON).
    document.querySelectorAll("input[type=checkbox][data-autocheck-when]").forEach((el) => {
      if (el.dataset.touched) return;
      if (matches(el, el.dataset.autocheckWhen)) {
        el.checked = true;
        el.dataset.autochecked = "1";
      } else if (el.dataset.autochecked) {
        el.checked = false;
        delete el.dataset.autochecked;
      }
    });
  };
  document.addEventListener("change", (event) => {
    if (event.target.matches && event.target.matches("[data-autocheck-when]")) {
      event.target.dataset.touched = "1";
    }
    refresh();
  });
  document.addEventListener("input", refresh);
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", refresh);
  else refresh();
})();
