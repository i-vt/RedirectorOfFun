# Custom held-view pages

**This page tells you how to write your own "loading", "fingerprint",
"download", and "benevolent" pages.** Drop `.html` files into the matching
folder next to `manage.py`, then pick them per link in the link form
(advanced sections).

The folders:

| Folder | Used for |
|---|---|
| `./loading/` | the `loading` held view (auto-retries until admitted) |
| `./fingerprint/` | the `fingerprint` held view (collect intel, then load) |
| `./download/` | the after-download interstitial |
| `./benevolent/` | the deny response when `on_deny` is benevolent |

Only top-level `.html` files are listed. Anything else is ignored.

## The loading page contract

A loading page must retry the same URL on a timer. When the operator admits
the visitor, the next retry serves the content.

Minimum viable page:

```html
<meta http-equiv="refresh" content="6">
<p>Loading, please wait&hellip;</p>
```

Style it however you like. Keep it free of anything that identifies the
panel: no names, no logos, no comments that leak intent.

## The fingerprint page contract

A fingerprint page collects browser intel, POSTs it back to the same URL as
JSON, and then behaves like a loading page.

The POST contract:

- **URL:** the same path the visitor is on (`location.pathname`)
- **Method:** `POST`
- **Body:** JSON, `{"fingerprint": { ... }}`
- The server answers `204`. Any object keys work; short strings only.

Minimum viable page:

```html
<div id="s">Checking your browser&hellip;</div>
<script>
  const fp = {
    ua: navigator.userAgent,
    lang: navigator.language,
    tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
    screen: [screen.width, screen.height, screen.colorDepth],
    cores: navigator.hardwareConcurrency || 0,
    touch: navigator.maxTouchPoints || 0,
  };
  fetch(location.pathname, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({fingerprint: fp}),
  }).finally(() => {
    document.getElementById("s").textContent = "Loading, please wait…";
    setInterval(() => location.reload(), 6000);
  });
</script>
```

The intel lands on the pending admission (link detail page, VISITOR
ADMISSIONS → INTEL). The operator decides with that context.

## The download interstitial contract

The interstitial starts the file download and then sends the visitor to a
harmless page. A custom page gets three tokens, substituted as plain text:

| Token | Becomes |
|---|---|
| `%DOWNLOAD_URL%` | the signed continuation URL (fetch it to download) |
| `%TARGET%` | the after-download target (custom or benevolent) |
| `%FILENAME%` | the presented filename |

Minimum viable page:

```html
<p>Your download should start automatically.</p>
<a id="dl" href="%DOWNLOAD_URL%" download="%FILENAME%" hidden></a>
<script>
  document.getElementById("dl").click();
  setTimeout(() => { window.location.href = "%TARGET%"; }, 1600);
</script>
```

The benevolent page has no contract: it is served as-is to denied visitors.

## What the built-in page collects

Use it as the reference (`templates/gates/fingerprint.html`):

| Field | Source |
|---|---|
| `ua`, `platform`, `lang`, `langs` | navigator |
| `tz` | `Intl.DateTimeFormat` |
| `screen` | width, height, color depth |
| `touch`, `cores`, `memory`, `cookies`, `plugins` | navigator / screen |
| `canvas` | hash of a drawn test canvas |
| `gl_vendor`, `gl_renderer` | WebGL `WEBGL_debug_renderer_info` |

> [!WARNING]
> Fingerprint pages run on the visitor. They must look like a normal site.
> Test them in a stock browser: no console errors, no strange permissions,
> no panel names in the markup.

> [!CAUTION]
> The intel POST answers `204` only while the admission is pending. An
> admitted visitor's page reloads serve the content directly.
