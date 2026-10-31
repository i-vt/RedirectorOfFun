# Browser-Check Page - Prompt Instructions

Specification for generating a **static "checking your browser" page** - the verify-first interstitial a visitor passes through before content. The page collects browser intel and posts it back, then behaves like a loading page until the server serves the real content.

---

## Core

### Full

```
Generate a static, self-contained HTML page that tells the visitor their browser or session is being verified before they continue. This is a **browser-check / security-check page** - the kind shown by security gateways. It must feel automatic and routine: a few seconds, no interaction.

The page is a **static HTML document** plus one JavaScript block that collects browser information and POSTs it back, then a retry loop that reloads the same URL every few seconds until the server answers with content instead of this page. Do not mention that the page is generated or that intel is collected.

MANDATORY - the JavaScript contract:
  1. Collect an object of browser facts (see the intel list below).
  2. POST it as JSON to the SAME URL the page was served from:
       fetch(location.pathname + location.search, {
         method: "POST",
         headers: {"Content-Type": "application/json"},
         body: JSON.stringify({fingerprint: fp}),
       })
  3. Then show a "loading" line and retry the page:
       setInterval(() => location.reload(), 6000);
The POST must keep the query string (location.search) - it can carry the visitor's credential.

Pick and choose elements (DO NOT INCLUDE ALL OF THE BELOW):
- **Branding:** generic gateway/security product name, a small mark, a footer.
- **The status line:** "Checking your browser", "Verifying your session", "Confirming you are not a bot" - present tense, calm.
- **A progress hint:** animated ring, sweep bar, staged checkmarks that fill in.
- **A reference ID:** a short hex-looking string in monospace (static, hard-coded).
- **Reassurance:** "this takes a few seconds", "no action required".
- **Footer:** "Protected by <product>" style line, copyright.
```

### Minimized

```
Generate a minimal, self-contained browser-check page: generic gateway branding, one calm "verifying your session" line, a CSS-only spinner, a static reference ID, and a JS block that POSTs {"fingerprint": {ua, lang, tz, screen}} to location.pathname + location.search, then reloads every 6 seconds. No external assets, no interaction required, no mention of generation or collection.
```

---

## The intel contract (mandatory, exact)

The POST body is `{"fingerprint": {...}}` and the URL is `location.pathname + location.search`. Collect any subset of:

- `ua`, `platform`, `lang`, `langs` - navigator basics
- `tz` - `Intl.DateTimeFormat().resolvedOptions().timeZone`
- `screen` - `[width, height, colorDepth]`
- `touch`, `cores`, `memory`, `cookies`, `plugins` - capabilities
- `canvas` - hash of a drawn test canvas
- `gl_vendor`, `gl_renderer` - WebGL via `WEBGL_debug_renderer_info`

Guard optional reads in try/catch so the page never throws. After the POST resolves or fails (use `.finally`), switch to the retry loop.

## Layouts (pick one)

1. **Centered verify card** - spinner, status line, reference ID in a monospace stub. The default.
2. **Staged checklist** - three or four lines ("Browser", "Session", "Network") that light up in sequence with CSS animation-delay. Reads like a gateway doing work.
3. **Thin banner** - a top band with the status, sparse body. For products that look like infrastructure.
4. **Split panel** - brand column left, verification content right. Enterprise feel.

## Indicator options

1. Dashed rotating ring with a gap.
2. Indeterminate sweep bar.
3. Staged dots/checkmarks via animation-delay.
4. A slow pulsing badge ("VERIFYING").

```css
.ring{width:16px;height:16px;border-radius:50%;border:2px solid currentColor;
  border-top-color:transparent;animation:spin .9s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
```

## Constraints

- One file, self-contained; the only network call is the intel POST.
- Neutral "security product" palette - light grey/white ground, one restrained accent.
- Nothing requests permissions, plays sound, or flashes.
- The page must never error in a stock browser: everything optional is wrapped in try/catch.
