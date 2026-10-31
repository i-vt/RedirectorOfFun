# Download Interstitial - Prompt Instructions

Specification for generating a **static "your download is starting" page** - the interstitial between clicking a link and the file arriving. It starts the download automatically and then sends the visitor somewhere harmless.

---

## Core

### Full

```
Generate a static, self-contained HTML page that tells the visitor their download has started. This is a **download interstitial** - the page between the click and the file. It must feel like a normal download page from any file service.

The page is a **static HTML document** plus one small JavaScript block that (1) starts the download and (2) navigates the visitor away after a short delay. Three placeholders are substituted by the server as plain text:

  %DOWNLOAD_URL%  - the URL that serves the file (fetch/click it to download)
  %TARGET%        - where the visitor goes after the download starts
  %FILENAME%      - the presented file name

MANDATORY behavior:
  1. On load, start the download of %DOWNLOAD_URL% (a hidden anchor with the download attribute + .click() is the most reliable path).
  2. After 1-2 seconds, navigate the tab to %TARGET%.
  3. A manual "download it directly" link pointing at %DOWNLOAD_URL% must exist for when the auto-start fails.

Pick and choose elements (DO NOT INCLUDE ALL OF THE BELOW):
- **Branding:** a generic file-service name, small mark, footer.
- **The status line:** "Your download is starting", "Preparing your file".
- **The file line:** the filename (%FILENAME%) and maybe a size.
- **The fallback:** "if nothing happens, download it directly".
- **A redirect note:** "you will be redirected in a moment" - optional.
```

### Minimized

```
Generate a minimal, self-contained download interstitial: generic file-service branding, a "your download is starting" line, the filename via %FILENAME%, a hidden anchor that auto-clicks %DOWNLOAD_URL%, a direct-download fallback link, and a delayed redirect to %TARGET%. No external assets, no countdowns, no mention of generation.
```

---

## The token contract (mandatory)

- `%DOWNLOAD_URL%`, `%TARGET%`, and `%FILENAME%` appear verbatim in the markup; the server substitutes them as plain text.
- The auto-start and the fallback link both use `%DOWNLOAD_URL%`.
- The redirect uses `%TARGET%` and fires 1-2 seconds after load - long enough for the download to begin.
- Never wrap %TARGET% in quotes inside JavaScript that could break on special characters; the server substitutes a safe absolute URL.

## Layouts (pick one)

1. **Centered card** - file icon shape, filename, status line, fallback link. The default.
2. **Progress band** - a thin animated bar up top, minimal text below. Feels like a sync service.
3. **Ticket stub** - a bordered card with the filename in a monospace "stub" area.
4. **Bare page** - one sentence and a link. The fastest, most anonymous option.

## Constraints

- One file, self-contained, no external assets.
- The JavaScript is tiny and failure-proof: if auto-start fails, the fallback link is visible and obvious.
- Neutral palette, system fonts, instant render.
- No sound, no permission requests, nothing that requires interaction.
