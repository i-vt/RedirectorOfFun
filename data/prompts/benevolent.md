# Benevolent Deny Page - Prompt Instructions

Specification for generating a **static denial/fallback page** shown to visitors who were refused. The page must look like an ordinary, boring answer from a normal server - not like something was hidden.

---

## Core

### Full

```
Generate a static, self-contained HTML page that answers a refused request with something routine. This is a **deny page** - a 404 not-found, a 403 access-denied, a parked-domain notice, an "account disabled" notice, or a maintenance page. The point is that nothing about it suggests a gate, a payload, or a decision.

The page is a **static HTML document**. No scripting, no live data, no retry loop (the denied visitor is done - they should leave). Branding and copy are hard-coded. Do not mention that the page is generated or that the refusal is deliberate.

Pick a denial flavor first (one per page):
- **404 Not Found** - the path does not exist. Dead ends are invisible.
- **403 Forbidden** - the server refuses without a reason.
- **Parked domain** - "this domain is registered, content coming soon" or a registrar-style placeholder.
- **Account suspended** - "this account has been suspended" hosting-provider notice.
- **Under construction** - a simple "we're working on it" page.

Pick and choose elements (DO NOT INCLUDE ALL OF THE BELOW):
- **A big status code or title** - the visual anchor.
- **One calm sentence** of explanation. No apology, no blame.
- **A link home** - to "/" of the same site, nothing external.
- **A reference line** - a static request ID in monospace.
- **Footer** - copyright, maybe a contact placeholder.
```

### Minimized

```
Generate a minimal, self-contained deny page: pick ONE flavor (404, 403, parked domain, account suspended, under construction), a big status anchor, one calm sentence, a link to "/", a static reference line, and a small footer. No JavaScript, no retry, no live data, no admission that the refusal is deliberate. Keep it boring and fast.
```

---

## Denial behavior (mandatory)

- The denied visitor's journey ENDS here. No refresh, no retry, no "wait a moment", no link forward.
- No status APIs, no countdowns, no dynamic anything. A denied page that moves looks staged.
- The tone is indifferent, not hostile. "Not found" and "suspended" are routine events on the real internet.

## Flavor layouts (pick one)

1. **Huge code, tiny copy** - oversized "404" dominating the page, one line under it. The classic.
2. **Letterhead notice** - brand top-left, rule, then a document-style notice. For "account suspended" flavors.
3. **Centered card** - small card with the title, sentence, and home link.
4. **Bare header + paragraph** - no boxes at all; heading, sentence, footer rule.
5. **Parked-domain panel** - domain name centered, "coming soon" line, optional "inquire" placeholder link.

## Details that sell it

- **A request ID** in monospace (`ref: 7f3a1c9d`) - static, hard-coded.
- **A date** near the footer (absolute, near today).
- **Server-ish footer text** - "nginx" style minimalism is optional; a product name works too.
- For parked domains: an "about this domain" line and a contact placeholder.

## Constraints

- One file, self-contained, no external assets.
- Zero JavaScript.
- Neutral palette, system fonts, instant render.
- Nothing on the page hints at redirection, gating, or a control plane.
