# Loading Page - Prompt Instructions

Specification for generating a **static "please wait" page** shown to visitors while they wait for operator admission. The page must retry the same URL on a timer - when the operator admits the visitor, the next retry serves the real content.

---

## Core

### Full

```
Generate a static, self-contained HTML page that tells the visitor content is loading. This is a **loading / please-wait page** for an online service - the kind shown while a document, portal, or download is being prepared. It reads as a normal part of the product, not an error and not a warning.

The page is a **static HTML document** plus one retry mechanism. There is no live data, no backend call, no status API. Branding, copy, and visuals are all hard-coded. Do not mention that the page is generated or that anything is simulated.

MANDATORY - the page must retry the same URL on a timer, using exactly one of:
  <meta http-equiv="refresh" content="6">
or
  setInterval(() => location.reload(), 6000);
Pick the meta refresh for maximum compatibility. The visitor must not need to click anything.

Pick and choose elements you want to include (DO NOT INCLUDE ALL OF THE BELOW):
- **Branding:** product name, logo mark, footer line. Keep it generic (a document portal, a sync service, a secure viewer).
- **The wait message:** one calm line - "Preparing your document", "Loading secure content", "Almost there". Present tense, no apology.
- **Progress indication:** an animated bar, ring, dots, or staged list - all CSS-only, no JavaScript required for the animation itself.
- **Time expectations:** a soft line like "This usually takes a few seconds" - never a countdown, never a specific end time.
- **Reassurance details:** "no need to refresh", "do not close this tab", "your file will open automatically".
- **Footer:** a support link placeholder and a copyright line.
```

### Minimized

```
Generate a minimal, self-contained loading page for a document service. Hard-code a product name, one calm "preparing your content" line, and a small CSS-only animation. The page MUST retry the same URL every 5-8 seconds with <meta http-equiv="refresh">. No JavaScript required beyond the animation, no countdown, no error tone, no mention that the page is generated. Keep it minimalistic and fast to paint.
```

---

## Retry handling (mandatory)

- The retry timer is the only dynamic behavior on the page. It is the mechanism that lets an admitted visitor through - never remove it.
- The refresh interval is 5-8 seconds. Faster looks broken, slower loses the visitor.
- Never show a retry button as the only path; the timer is the path.
- Never include a link away from the page (the visitor must stay until admitted).

## Layouts (pick one)

1. **Centered spinner card** - one small card, spinner top, one line under it. The default, always safe.
2. **Progress band** - a thin full-width progress bar pinned to the top edge, one centered line of text below. Reads like a web app boot screen.
3. **Document skeleton** - grey placeholder blocks where the "content" will appear (a fake page outline), with a small status line. Strongest illusion that a document is arriving.
4. **Bottom sheet** - content pinned to the lower third: animation, message, footer. Unusual but plausible for mobile-first products.
5. **Left rail** - narrow brand column on the left, loading content in the main area. Reads like an internal tool.
6. **Terminal line** - monospace lines that look like a sync log (static text, not typing). For technical audiences.

## Indicator options

*Animated, CSS-only*

1. Indeterminate sweep bar (2px track, sliding segment).
2. Rotating ring with a gap (border + transparent quadrant).
3. Three dots pulsing in sequence (nth-child delay).
4. Skeleton shimmer across placeholder blocks (`linear-gradient` sweep).
5. Circular percentage-less spinner made of dashes.

```css
.dots i{display:inline-block;width:6px;height:6px;border-radius:50%;background:currentColor;margin:0 3px;opacity:.25;animation:p 1.2s infinite}
.dots i:nth-child(2){animation-delay:.15s}.dots i:nth-child(3){animation-delay:.3s}
@keyframes p{40%{opacity:1}}
```

## Constraints

- No external assets, no fonts, no CDN calls - one file, self-contained.
- Neutral palette only (light grey/white ground, one muted accent). Nothing alarming.
- No sound, no vibration, no permission requests.
- The page must render instantly - inline the CSS.
