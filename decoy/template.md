# Maintenance Page — Prompt Instructions

Specification for generating a **static, self-contained maintenance / scheduled-downtime page** for an online software platform. Companion to the incident-page spec; same constraints, different subject matter.

---

## Core

### Full

```
Generate a static HTML/CSS/JS-free, self-contained page. This is a **scheduled-maintenance page** / **planned-downtime notice** (or something similar) for an online software platform. It explains that the service is temporarily unavailable or read-only while planned work is carried out; it states the maintenance window, what is affected, what still works, what customers should do in the meantime, and when service is expected to return. It may include a short history of updates, a notification sign-up panel, and standard support and legal links.

The page is essentially a **static HTML document**. Branding, navigation, the maintenance notice, window metadata, affected-component list, guidance, and footer are all hard-coded rather than pulled from a live system. There is no scripting to count down, poll, or refresh — any "time remaining" figure is a pre-computed string that becomes stale the moment the window passes. Navigation, notification, and footer links are placeholders. Apart from a small CSS-based status animation, the page has no dynamic behavior; updating its content requires editing the HTML directly.

Make a deterministic choice and pick-and-choose what elements to include from the list below (not all are needed, some may be entirely skipped). Fabricate any element as long as it is realistic — do not include the words saying you are making it look realistic or that it is a faux page. You may choose to make a small page with a single notice, or a fuller page with a window table and component list (pick the size and detail at random).

Pick and choose elements you want to include (DO NOT INCLUDE ALL OF THE BELOW)
- **Branding and presentation:** organization name, product name, logo, navigation labels, layout, and visual styling.
- **Maintenance identification:** title, maintenance reference ID, type (scheduled / emergency / rolling), change category, and the date the window was announced.
- **Current state:** scheduled, in progress, extended, verifying, or complete; whether the window is on time, running long, or finished early.
- **Window details:** scheduled start, scheduled end, total duration, elapsed time, time remaining, timezone and UTC offset, and the next expected update.
- **Impact scope:** affected components, regions, customer segments, features fully unavailable vs. read-only vs. degraded, and what remains operational throughout.
- **Component health:** the number of listed services, their descriptions, and their individual statuses (unavailable / read-only / unaffected).
- **Timeline content:** pre-announcement, window opened, milestones, verification steps, and closure notice. IMPORTANT: VALUES MUST BE STATIC AND CLOSE TO TODAY'S TIME/DATE — VERIFY VIA THE WEB IF NEEDED.
- **Technical explanation:** what is being changed, why, expected benefit, whether any action is required from customers, and whether behaviour changes after completion.
- **Customer guidance:** what to do before/during the window (save work, finish in-flight transactions, pause integrations), what not to do, retry behaviour after completion, and where data will be on return.
- **Communication options:** subscribe to updates by email or text, status-page links, support contact details, escalation path.
- **Footer content:** copyright, policy links, support links, and additional resources.
```

### Minimized

```
Generate a static, self-contained HTML/CSS page for a fictional online software platform's scheduled maintenance window.

Core content (hard-coded, no live data):

    Branding: organization/product name, simple navigation
    Maintenance: title, reference ID, window (start and end, near today's date/time — start between 1 hour ago and 8 hours from now), one line on what is affected
    Footer: support links, legal links, copyright

Constraints:

    Static HTML document — no JavaScript, no countdown, no auto-refresh, no polling
    All content hard-coded; updating requires editing HTML directly
    Small CSS-based status animation allowed (e.g. pulsing indicator, sweeping bar)
    Links are placeholders
    Do not mention the page is fictional or that elements are fabricated

Pick and choose — include only a subset of the above (e.g. just a notice and a window line, or a fuller page with a component table and guidance). Vary the size and detail randomly. Make it minimalistic.
```

---

## Time handling (maintenance-specific, mandatory)

Because the page cannot compute anything, all time values are frozen text. Rules:

- Always show **absolute timestamps** with an explicit timezone or UTC offset — never relative-only ("in 2 hours").
- If a "time remaining" line is included, it must be a **pre-computed string** presented as an estimate, and the absolute end time must appear alongside it.
- Mark up timestamps as `<time datetime="…">` with a machine-readable ISO value, even though nothing reads it.
- Never imply a live countdown, never write copy that only makes sense at one instant ("The window closes in 40 minutes"), and never animate digits downward.
- Prefer wording that stays true for the life of the page: *"The window is scheduled to close at 04:00 UTC."* over *"Closing in 2h 14m."*
- Include a **"last reviewed"** or **"last updated"** line so a stale page is at least honest about its age.

---

## Styling

### Page-level layouts (pick one)

1. **Centered single card** — one narrow column (~560–640px), vertically centered, small footer beneath. Best for the stripped-back version: title, reference, window, one status line.
2. **Full-bleed typographic header + short body** — oversized maintenance title spanning the viewport, thin rule, three or four metadata lines beneath, footer pinned low. Reads as an announcement.
3. **Split layout** — left column fixed (status word + indicator + reference + window), right column scrolling detail, component list, guidance. Strong hierarchy at any width.
4. **Nav rail + main** — thin left sidebar with product name and 3–4 nav links; main area holds the notice. Closest to a real product shell.
5. **Pinned ribbon + minimal body** — thin full-width banner at the top carrying status and window, everything else in a sparse column below. Reads as a system notice.
6. **Letterhead / memo** — brand top-left, horizontal rule, left-aligned metadata block (monospace reference, window times), body paragraph, rule, footer. Document-like, almost no boxes.
7. **Poster** — huge headline, tiny metadata, generous negative space, no containers. Only viable when content is very short.
8. **Asymmetric diagonal split** — two blocks meeting at an angled edge (`clip-path`); status above, detail below. Adds shape without colour.

### Maintenance-block formats

9. **Window bar** — a single full-width horizontal band with the start time at the left edge and the end time at the right, a hairline between them, and a filled segment marking the scheduled span. Static, no moving playhead.
10. **Horizontal stepper** — 3–4 segments (Scheduled → In progress → Verifying → Complete), current one filled or outlined. Sits under the title.
11. **Ticket / boarding-pass** — bordered card with a perforation (dashed line) and a notched edge; reference ID set large in a monospace stub, window times in the body.
12. **Definition list** — two-column rows (label left, value right) separated by hairlines: Reference, Opens, Closes, Duration, Affected, Status. No cards, no shadows.
13. **Stat tiles** — 3–4 small equal boxes: status, window, affected services, last reviewed. Grid-based, scan-friendly.
14. **Log/table** — time column + message column, monospace, hairline rows. Signals "system record."
15. **Console block** — inset bordered rectangle, monospace, prefixed lines (`> window: 2026-10-25T02:00Z → 04:00Z`). One shape, zero decoration.
16. **Chip cluster** — affected services as outlined pills under a single sentence, with a second cluster for "stays online."
17. **Radial indicator** — a circle (ring or partial arc) carrying the status word inside, window metadata radiating below. One strong geometric anchor.
18. **Read-only matrix** — small grid of service names × capability (read / write / API), each cell a glyph. Compact way to express partial availability.

### Shape devices worth mixing in

- **Borders over fills**: 1px hairlines, no shadows, square or 2px radius — reads more "status page" than rounded card.
- **Native `<details>/<summary>`** for a collapsed "planned changes" or "previous updates" block — still zero JavaScript.
- **Sticky label column** on the left with values on the right, so long content stays anchored.
- **Notched/perforated edges** (radial-gradient mask) or **corner cut** (`clip-path`) for one distinctive shape.
- **Off-centre column** (e.g. 1/3–2/3 grid with content pushed right) — minimalism without the default centred stack.
- **Full-width hairline rules** at irregular intervals to break sections without boxes.
- **Oversized reference ID** as the visual anchor instead of a logo.
- **Time-ruler motif** — tick marks along a rule at regular intervals, with two labelled ends, used as a section divider.

### Indicator options

*Animated (in-progress states)*

1. Indeterminate sweep bar — a short segment slides along a 2px track. "In progress" without demanding attention.
```css
.bar{position:relative;height:2px;background:currentColor;opacity:.18;overflow:hidden}
.bar::after{content:"";position:absolute;inset:0;width:35%;background:currentColor;
  animation:sweep 1.9s cubic-bezier(.4,0,.6,1) infinite}
@keyframes sweep{from{transform:translateX(-100%)}to{transform:translateX(320%)}}
```
2. Rotating dashed ring / arc — 1.5px circle with one transparent quadrant; the gap reads as "working."
```css
.ring{width:14px;height:14px;border:1.5px solid currentColor;border-right-color:transparent;
  border-radius:50%;animation:spin 1.1s linear infinite}
@keyframes spin{to{transform:rotate(1turn)}}
```
3. Equalizer bars — three 2px bars scaling on staggered delays. Conveys activity level rather than alert.
4. Marching dashes — a hairline of dashes translating along its own track. Very quiet; works as a rule under the heading.
5. Scanning line — a 1px vertical line sweeps left→right across a bordered box or the reference-ID block.
6. Breathing tracking — the status word expands and contracts its letter-spacing. Nothing blinks; the text just moves.
```css
.status{animation:track 3.2s ease-in-out infinite}
@keyframes track{0%,100%{letter-spacing:.04em}50%{letter-spacing:.16em}}
```
7. Shimmer / skeleton wipe — a translucent gradient band slides across a muted block, e.g. the "next update" region.
8. Rotating square — a 6px square rotating in 90° steps(4) increments. Mechanical, tick-like, unmistakably "system."
9. Cycling ellipsis — `In progress` → `.` → `..` → `...` via `@keyframes` on `::after` content with `steps(1)` so it snaps rather than blinks.

*Static shapes (preferred for scheduled-not-yet-started and completed states, and for reduced motion)*

10. Glyph set — ■ in progress, ◧ read-only, □ scheduled, ╱ complete. One character, no animation, fully semantic.
11. Half-filled square or circle — linear-gradient split inside a bordered box; fill proportion maps to how far through the window the page believes it is.
12. Hatch fill — a bordered box filled with 45° hairlines signals "work underway" with zero movement.
13. Tick marks — a short row of 5 hairlines where 3 are solid and 2 faint. Progress bar with no colour.
14. Corner notch — a clipped corner (`clip-path`) on the notice block to distinguish "in progress" from a plain card at a glance.
15. Struck-through label — completed state as ~~MAINTENANCE~~ or `MAINTENANCE` with a thin slash mark after the word.
16. Status word as the indicator — `MAINTENANCE WINDOW` in small caps, letter-spaced, with a hairline rule beneath. Typography carries the state; no glyph needed.

*Structural cues*

17. Border weight as signal — 2px border on the notice block vs. 1px hairlines elsewhere.
18. Inset vs. outset — the notice block inset (recessed) while everything else sits flush; reads as "system area."
19. Sticky status rail — status word fixed to the viewport edge on scroll; presence replaces the need to animate anything.

---

## Copy rules

- **Lead with the window**, not the apology. State start, end, and timezone in the first two lines.
- Say what **still works** as prominently as what doesn't — read-only access, mobile app, exports, API caching.
- No countdown language, no "any minute now", no promises the page can't keep.
- Give one clear instruction for users: finish in-flight work before the window, retry after the stated end time, contact support if something looks wrong afterwards.
- Mention data safety explicitly if writes are blocked.
- If the window has already been extended, show it: original end time struck through, new end time beside it, and a one-line reason.
- Keep the tone flat and operational. No exclamation marks, no mascots, no "we're making things even better!"

---

## Constraints

- Static, self-contained HTML document — inline or embedded CSS, no external assets required to render.
- **No JavaScript.** No countdowns, no polling, no `Date.now()`, no auto-refresh meta tag.
- All content hard-coded; editing the HTML is the only way to update it.
- Links are placeholders (`#` or plausible-looking paths) — no real destinations.
- Do not state that the page, company, or event is fictional.
- One small CSS animation at most, and only if the status warrants it.

---

# Incident Page

## Core

### Full

```
Generate a static HTML/CSS/JS self-contained page. This is a **service-status incident page** / **service down** page (or something similar) for an online software platform. It describes a service disruption or website issues, it may summarize its impact and duration, it may explain that a fix has been applied while monitoring continues, and lists the health of related components. It may contain a chronological timeline documents the incident’s progress, followed by a notification section and standard support and legal links.

The page is essentially a **static HTML document**. It may have branding, navigation, incident summary, impact details, component-status list, timeline entries, notification panel, and footer are all hard-coded rather than retrieved from a live status system. There is no scripting to refresh the information automatically, and the navigation, notification, and footer links are placeholders. Apart from a small CSS-based status animation, the page has no dynamic behavior; updating its content would require editing the HTML directly.

Make deterministic choice and pick-and-choose what elements to include from the list below (not all are needed, some may be entirely skipped), you may fabricate any element as long as it is realistic (do not actually include the words that you're trying to make it look realistic nor that it is a faux page). You may choose to make a simple small page with a simple "error" or a full page with all of the elements (pick randomly the size of the page and elements to include).

Pick and choose elements that you want to include in the page (DO NOT INCLUDE ALL OF THE BELOW ELEMENTS)
- **Branding and presentation:** organization name, product name, logo, navigation labels, layout, and visual styling.
- **Incident identification:** incident title, reference number, category, and opening date.
- **Current state:** severity, operational status, affected service area, and whether the incident is under investigation, being monitored, or resolved.
- **Impact details:** affected components, customer segments, regions, symptoms, duration, and expected recovery or next-update estimates.
- **Component health:** the number of listed services, their descriptions, and their individual statuses.
- **Timeline content:** the number and order of updates, timestamps, investigation milestones, resolution steps, and closure notices. IMPORTANT VALUES HAVE TO BE STATIC AND CLOSE TO THE TODAY'S TIME/DATE, VERIFY VIA THE WEB IF NEEDED THE CURRENT TIME/DATE.
- **Technical explanation:** how much information is provided about the cause, fix, recurrence prevention, or post-incident review.
- **Customer guidance:** workarounds, recommended actions, retry behavior, and instructions for affected users.
- **Communication options:** email, text, or other notification methods, plus support contact details.
- **Footer content:** copyright information, policy links, support links, and additional resources.


MAY = decide whether it should have it, optional and not necessary. Just an option.
```

### Minimized
```
Generate a static, self-contained HTML/CSS page for a fictional online (pick any random name that sounds realistic or feasible) software platform's service disruption.
Core content (hard-coded, no live data):

    Branding: organization/product name, simple navigation
    Incident: title, reference number, opening date (near today's date/time minus 4 to 12 hours.)
    Footer: support links, legal links, copyright

Constraints:

    Static HTML document — no JavaScript, no auto-refresh, no dynamic behavior
    All content hard-coded; updating requires editing HTML directly
    Small CSS-based status animation allowed (e.g., pulsing indicator)
    Links are placeholders
    Do not mention the page is fictional or that elements are fabricated

Pick and choose — include only a subset of the above (e.g., just an error message and component list, or a fuller page with timeline and notifications). Vary the size and detail randomly. Make it minimalistic. 
```

## Styling

### Page-level layouts (pick one)

1. **Centered single card** — one narrow column (~560–640px), vertically centered, small footer beneath. Best for a stripped-back version: title, ref, timestamp, one-line status.
2. **Full-bleed typographic header + short body** — oversized incident title spanning the viewport, thin rule, three or four metadata lines beneath, footer pinned low. Feels like an announcement, not a dashboard.
3. **Split layout** — left column fixed (status word + pulsing dot + reference), right column scrolling detail/timeline. Strong hierarchy, works at any width.
4. **Nav rail + main** — thin left sidebar with product name and 3–4 nav links; main area holds the incident. Closest to a "real product" shell.
5. **Pinned ribbon + minimal body** — thin full-width banner at the top carrying the status and reference, everything else in a sparse column below. Reads as a system notice.
6. **Letterhead / memo** — brand at top-left, horizontal rule, left-aligned metadata block (monospace ref, date), body paragraph, rule, footer. Document-like, almost no boxes.
7. **Poster** — huge headline, tiny metadata, generous negative space, no containers at all. Only viable when content is very short.
8. **Asymmetric diagonal split** — two blocks meeting at an angled edge (clip-path); status above, detail below. Adds shape without color.

### Incident-block formats

9. **Vertical timeline rail** — hairline with dot markers; each entry is a timestamp + one line. Ideal if you include a timeline.
10. **Horizontal stepper** — 3–4 segments (Investigating → Identified → Monitoring → Resolved), current one filled or outlined. Compact, sits under the title.
11. **Ticket / boarding-pass** — bordered card with a perforation (dashed line) and a notched edge; reference number set large in a monospace stub. Very literal "incident ticket."
12. **Definition list** — two-column rows (label left, value right) separated by hairlines: Reference, Opened, Affected, Status. No cards, no shadows.
13. **Stat tiles** — 3–4 small equal boxes: status, elapsed time, affected services, last update. Grid-based, scan-friendly.
14. **Log/table** — time column + message column, monospace, hairline rows. Signals "system record."
15. **Console block** — inset bordered rectangle, monospace, prefixed lines (`> status: degraded`). One shape, zero decoration.
16. **Chip cluster** — affected services as outlined pills/pills with rounded ends under a single sentence.
17. **Radial indicator** — a circle (ring or partial arc) carrying the status word inside, metadata radiating below. Only if you want one strong geometric anchor.

### Shape devices worth mixing in

- **Borders over fills**: 1px hairlines, no shadows, square or 2px radius — reads more "status page" than rounded cards.
- **Native `<details>/<summary>`** for a collapsed "previous updates" block — still zero JavaScript.
- **Sticky label column** on the left with values on the right, so long content stays anchored.
- **Notched/perforated edges** (radial-gradient mask) or **corner cut** (`clip-path`) for a single distinctive shape.
- **Off-center column** (e.g. 1/3–2/3 grid with the content pushed right) — minimalism without the default centered stack.
- **Full-width hairline rules** at irregular intervals to break sections without boxes.
- **Oversized reference number** as the visual anchor instead of a logo.

### Status indicator options

1. Indeterminate sweep bar — a short segment slides along a 2px track. Reads "in progress" without demanding attention.

```css
.bar{position:relative;height:2px;background:currentColor;opacity:.18;overflow:hidden}
.bar::after{content:"";position:absolute;inset:0;width:35%;background:currentColor;
  animation:sweep 1.9s cubic-bezier(.4,0,.6,1) infinite}
@keyframes sweep{from{transform:translateX(-100%)}to{transform:translateX(320%)}}
```

2. Rotating dashed ring / arc — 1.5px circle with one transparent quadrant; the gap reads as "working."

```css
.ring{width:14px;height:14px;border:1.5px solid currentColor;border-right-color:transparent;
  border-radius:50%;animation:spin 1.1s linear infinite}
@keyframes spin{to{transform:rotate(1turn)}}
```

3. Equalizer bars — three 2px bars scaling on staggered delays. Conveys "activity level" rather than "alert."

```css
.bars{display:flex;gap:2px;align-items:flex-end;height:12px}
.bars i{width:2px;height:100%;background:currentColor;transform-origin:bottom;
  animation:eq 1.2s ease-in-out infinite}
.bars i:nth-child(2){animation-delay:.15s}
.bars i:nth-child(3){animation-delay:.3s}
@keyframes eq{0%,100%{transform:scaleY(.25)}50%{transform:scaleY(1)}}
```

4. Marching dashes — a hairline of dashes translating along its own track. Very quiet, works as a rule under the heading.

```css
.dash{height:2px;background:repeating-linear-gradient(90deg,currentColor 0 6px,transparent 6px 12px);
  animation:march 1s linear infinite}
@keyframes march{to{background-position:12px 0}}
```

5. Scanning line — a 1px vertical line sweeps left→right across a bordered box or the reference-number block.

6. Breathing tracking — the status word itself expands and contracts its letter-spacing. Nothing blinks; the text just moves.

```css
.status{animation:track 3.2s ease-in-out infinite}
@keyframes track{0%,100%{letter-spacing:.04em}50%{letter-spacing:.16em}}
```

7. Glitch offset — two pseudo-element copies of the status word nudge 1–2px on a steps() timing. Suggests instability rather than an alert.

8. Shimmer / skeleton wipe — a translucent gradient band slides across a muted block (e.g. the "last updated" placeholder region).

9. Odometer tick — elapsed-time digits roll on a steps() keyframe. Ties motion to real content instead of a decorative lamp.

10. Rotating square — a 6px square rotating in 90° steps(4) increments. Mechanical, tick-like, unmistakably "system."
*Text-based replacements (no motion at all)*

11. Cycling ellipsis — Investigating → . → .. → ... via @keyframes on ::after content. Uses steps(1) so it snaps rather than blinks.

12. Status word as the indicator — set MONITORING in small caps, letter-spaced, with a hairline rule beneath. The typography carries the state; no glyph needed.

13. Struck-through label — resolved state as RESOLVED with a thin line through it, or a small slash mark after the word.
*Static shapes that encode state (best for reduced-motion)*

14. Glyph set — ■ active, ◧ degraded, □ monitoring, ╱ resolved. One character, no animation, fully semantic.

15. Half-filled square or circle — linear-gradient split inside a bordered box; fill proportion maps to severity.

16. Hatch fill — a bordered box filled with 45° hairlines signals "in progress" without any movement.

17. Tick marks — a short row of 5 hairlines where 3 are solid and 2 are faint. Progress bar with no fill color.

18. Corner notch — a clipped corner (clip-path) on the incident card distinguishes "degraded" layout from a plain card at a glance.
*Structural cues*

19. Border weight as signal — 2px border on the incident block vs. 1px hairlines elsewhere. Emphasis without a lamp.

20. Inset vs. outset — the incident block inset (recessed) while everything else sits flush; reads as "system area."

21. Sticky status rail — status word fixed to the viewport edge on scroll; presence replaces the need to animate anything.

22. Blinking light

### Color schemes

Here are 100 visually pleasant website color schemes using general color descriptions. Each scheme includes a primary background, secondary surface, text color, and accent color.

1. White background, light grey surface, dark grey text, soft blue accent  
2. Cream background, beige surface, brown text, burnt orange accent  
3. Light grey background, white surface, charcoal text, teal accent  
4. Soft white background, pale blue surface, navy text, coral accent  
5. Pale mint background, white surface, dark green text, lime accent  
6. Light peach background, cream surface, chocolate text, dusty rose accent  
7. Off-white background, light lavender surface, dark purple text, magenta accent  
8. Pale yellow background, white surface, olive text, mustard accent  
9. Light blue-grey background, white surface, slate text, sky blue accent  
10. Soft beige background, tan surface, espresso text, terracotta accent  

11. White background, light mint surface, dark teal text, emerald accent  
12. Pale pink background, blush surface, maroon text, gold accent  
13. Light grey background, off-white surface, black text, electric blue accent  
14. Cream background, sand surface, dark brown text, sage accent  
15. Pale lavender background, lilac surface, indigo text, violet accent  
16. White background, pale grey surface, dark blue text, orange accent  
17. Light green background, mint surface, forest text, yellow-green accent  
18. Soft grey background, white surface, steel text, red accent  
19. Pale blue background, ice surface, midnight text, cyan accent  
20. Off-white background, light peach surface, rust text, peach accent  

21. White background, pale yellow surface, dark grey text, lemon accent  
22. Light beige background, cream surface, taupe text, olive accent  
23. Pale grey background, white surface, navy text, turquoise accent  
24. Soft white background, light pink surface, plum text, hot pink accent  
25. Mint background, white surface, dark green text, seafoam accent  
26. Light blue background, pale grey surface, denim text, orange accent  
27. Cream background, ivory surface, dark red text, crimson accent  
28. White background, light lavender surface, grey text, purple accent  
29. Pale green background, white surface, moss text, chartreuse accent  
30. Light grey background, off-white surface, dark text, green accent  

31. Soft yellow background, cream surface, brown text, amber accent  
32. White background, pale blue surface, steel text, royal blue accent  
33. Light peach background, white surface, coral text, red-orange accent  
34. Pale mint background, light grey surface, dark teal text, aqua accent  
35. Off-white background, beige surface, chocolate text, bronze accent  
36. Light grey background, white surface, indigo text, pink accent  
37. White background, pale green surface, dark grey text, bright green accent  
38. Cream background, light yellow surface, olive text, gold accent  
39. Pale lavender background, white surface, purple text, lavender accent  
40. Light blue-grey background, off-white surface, navy text, red accent  

41. Soft white background, pale pink surface, dark red text, rose accent  
42. Light beige background, white surface, brown text, copper accent  
43. Pale grey background, light blue surface, dark blue text, light blue accent  
44. White background, cream surface, charcoal text, yellow accent  
45. Mint background, pale green surface, forest text, green accent  
46. Light grey background, white surface, black text, blue accent  
47. Off-white background, light peach surface, rust text, orange accent  
48. Pale yellow background, white surface, dark grey text, black accent  
49. Light blue background, ice surface, steel text, dark blue accent  
50. Cream background, light lavender surface, indigo text, blue accent  

51. White background, pale grey surface, dark text, coral accent  
52. Soft grey background, off-white surface, navy text, teal accent  
53. Pale pink background, blush surface, maroon text, red accent  
54. Light green background, white surface, dark green text, lime accent  
55. White background, pale blue surface, denim text, sky accent  
56. Cream background, sand surface, espresso text, brown accent  
57. Pale lavender background, lilac surface, purple text, violet accent  
58. Light grey background, white surface, dark grey text, orange accent  
59. Off-white background, light mint surface, teal text, emerald accent  
60. Pale blue background, white surface, midnight text, cyan accent  

61. Soft white background, light yellow surface, olive text, mustard accent  
62. Light beige background, cream surface, taupe text, tan accent  
63. White background, pale pink surface, plum text, pink accent  
64. Pale grey background, off-white surface, charcoal text, red accent  
65. Mint background, white surface, forest text, seafoam accent  
66. Light blue background, pale grey surface, steel text, blue accent  
67. Cream background, ivory surface, dark red text, crimson accent  
68. White background, light lavender surface, grey text, purple accent  
69. Pale green background, white surface, moss text, green accent  
70. Light grey background, off-white surface, dark text, turquoise accent  

71. Soft yellow background, cream surface, brown text, gold accent  
72. White background, pale blue surface, navy text, royal accent  
73. Light peach background, white surface, coral text, orange accent  
74. Pale mint background, light grey surface, dark teal text, aqua accent  
75. Off-white background, beige surface, chocolate text, bronze accent  
76. Light grey background, white surface, indigo text, violet accent  
77. White background, pale green surface, dark grey text, bright accent  
78. Cream background, light yellow surface, olive text, amber accent  
79. Pale lavender background, white surface, purple text, magenta accent  
80. Light blue-grey background, off-white surface, navy text, red accent  

81. Soft white background, pale pink surface, dark red text, rose accent  
82. Light beige background, white surface, brown text, copper accent  
83. Pale grey background, light blue surface, dark blue text, sky accent  
84. White background, cream surface, charcoal text, yellow accent  
85. Mint background, pale green surface, forest text, lime accent  
86. Light grey background, white surface, black text, blue accent  
87. Off-white background, light peach surface, rust text, terracotta accent  
88. Pale yellow background, white surface, dark grey text, black accent  
89. Light blue background, ice surface, steel text, dark accent  
90. Cream background, light lavender surface, indigo text, purple accent  

91. White background, pale grey surface, dark text, teal accent  
92. Soft grey background, off-white surface, navy text, coral accent  
93. Pale pink background, blush surface, maroon text, pink accent  
94. Light green background, white surface, dark green text, green accent  
95. White background, pale blue surface, denim text, blue accent  
96. Cream background, sand surface, espresso text, brown accent  
97. Pale lavender background, lilac surface, purple text, violet accent  
98. Light grey background, white surface, dark grey text, orange accent  
99. Off-white background, light mint surface, teal text, emerald accent  
100. Pale blue background, white surface, midnight text, cyan accent

---

# 403 Access Denied Page

Specification for a **static, self-contained access-denied page** for an online software platform. The page explains that the requested resource cannot be accessed with the current permissions and offers a safe next step without exposing sensitive details.

## Core

### Full

```
Generate a static, self-contained HTML/CSS page for an online software platform's 403 Access Denied response. It explains that access is restricted because the user lacks permission, the session is not authorized, or the resource belongs to another workspace. It may provide a request ID, a few appropriate next steps, and standard support and legal links.

The page is essentially a static HTML document. Branding, navigation, the error message, access metadata, guidance, and footer are all hard-coded rather than retrieved from a live authorization system. There is no scripting to check permissions, redirect the visitor, or refresh the page. Links are placeholders, and updating the content requires editing the HTML directly.

Make a deterministic choice and include only a subset of the elements below. Fabricate realistic details where needed, but do not state that the page or its contents are fictional. Choose either a compact access notice or a fuller page with metadata and guidance.

- **Branding and presentation:** organization name, product name, logo, navigation labels, layout, and visual styling.
- **Error identification:** 403 status code, Access Denied or Forbidden title, request ID, and a short error category.
- **Access context:** signed-out or insufficient-permissions state, workspace or organization context, and whether authentication or authorization is the likely issue.
- **Available actions:** return to the previous area, go to the dashboard, switch workspace through a placeholder link, or contact an administrator.
- **Support details:** request ID to quote, support contact, and a brief note about what information to include.
- **Footer content:** copyright, policy links, support links, and additional resources.

Do not reveal private resource names, internal permission rules, user records, or whether a sensitive resource exists. Do not imply that the page can verify the visitor's identity or permissions.
```

### Minimized

```
Generate a static, self-contained HTML/CSS 403 Access Denied page for an online software platform.

Core content (hard-coded, no live data):

    Branding: organization or product name
    Error: 403, Access Denied title, one-sentence explanation
    Action: one safe next step, such as returning to the dashboard
    Footer: support link and copyright

Constraints:

    No JavaScript, redirects, permission checks, or auto-refresh
    All content hard-coded; links are placeholders
    Do not expose sensitive resource or account details
    Do not mention that the page is fictional or fabricated

Include only a subset of the optional content. Make it minimalistic.
```

## Styling

### Page-level layouts (pick one)

1. **Centered access card** — status code above a short explanation and one primary placeholder link.
2. **Split permission panel** — large `403` on the left, access guidance and request ID on the right.
3. **Letterhead notice** — product name, restrained heading, metadata rows, and a document-like footer.
4. **Pinned product shell** — simple top navigation with a sparse access notice in the main area.
5. **Typographic poster** — oversized `403`, minimal copy, and generous negative space.

### Shape devices

- Use a lock, keyhole, barred doorway, or blocked-path motif as simple CSS geometry or inline decoration.
- Use a two-column definition list for Request ID, Access, and Support.
- Use a stepped path ending before a threshold to communicate restricted access without animation.
- Prefer borders, muted surfaces, and one restrained accent over alarm-style visuals.

## Copy rules

- State clearly that the current account or session cannot access the requested area.
- Offer only plausible actions; do not promise that signing in again will restore access.
- If permissions may be required, direct the visitor to their workspace administrator.
- Keep the tone neutral and avoid accusing the visitor of wrongdoing.
- Do not include sensitive implementation, authorization, or resource details.

## Constraints

- Static, self-contained HTML with embedded CSS and no external assets required to render.
- No JavaScript, redirects, permission checks, session detection, or auto-refresh.
- All links are placeholders, and all content is hard-coded.
- Do not state that the page, company, or event is fictional.

---

# 404 Not Found Page

Specification for a **static, self-contained not-found page** for an online software platform. The page explains that the requested address does not lead to an available page and helps the visitor recover without pretending to perform a live search.

## Core

### Full

```
Generate a static, self-contained HTML/CSS page for an online software platform's 404 Not Found response. It explains that the page may have moved, the address may be incorrect, or the link may be outdated. It provides a small set of useful recovery routes and may include a request ID or static support details.

The page is essentially a static HTML document. Branding, navigation, the error message, recovery links, and footer are hard-coded. There is no scripting to inspect the URL, search content, redirect visitors, or record the missing route. Navigation and support links are placeholders, and updating the page requires editing the HTML directly.

Make a deterministic choice and include only a subset of the elements below. Fabricate realistic details where needed, but do not state that the page or its contents are fictional. Choose either a minimal not-found notice or a fuller recovery page.

- **Branding and presentation:** organization name, product name, logo, navigation labels, layout, and visual styling.
- **Error identification:** 404 status code, Page Not Found title, and a concise explanation.
- **Possible causes:** outdated bookmark, moved page, renamed resource, or mistyped address.
- **Recovery routes:** home, dashboard, documentation, status, support, or a previous-area placeholder link.
- **Optional resource hints:** two or three plausible destination labels without presenting them as personalized recommendations.
- **Support details:** request ID, contact link, and guidance to quote the original address when reporting a broken link.
- **Footer content:** copyright, policy links, support links, and additional resources.

Do not claim that a search was performed, that the URL was checked live, or that the visitor was automatically redirected. Avoid implying that a missing private resource exists.
```

### Minimized

```
Generate a static, self-contained HTML/CSS 404 Not Found page for an online software platform.

Core content (hard-coded, no live data):

    Branding: organization or product name, simple navigation
    Error: 404, Page Not Found title, one-sentence explanation
    Recovery: home or dashboard link, optional support link
    Footer: legal links and copyright

Constraints:

    No JavaScript, live search, URL inspection, redirects, or auto-refresh
    All content hard-coded; links are placeholders
    Do not claim that recommendations are personalized
    Do not mention that the page is fictional or fabricated

Include only a subset of the optional content. Make it minimalistic.
```

## Styling

### Page-level layouts (pick one)

1. **Broken-path composition** — a route line with a visible gap leading from the error message to recovery links.
2. **Oversized code poster** — huge `404` with a small title, one explanation, and two links.
3. **Centered wayfinding card** — compact notice with a vertical list of likely destinations.
4. **Split map layout** — error statement on one side and a simple directory-style link list on the other.
5. **Margin-note layout** — small brand header, left-aligned message, and metadata pushed into a narrow side column.

### Shape devices

- Use a missing puzzle piece, disconnected nodes, an empty shelf, or a broken breadcrumb trail as restrained visual motifs.
- Set recovery links as a definition list, compact directory, or outlined chip cluster.
- Use an empty rectangular frame as the visual anchor rather than a decorative illustration.
- Keep the page visually lighter than an outage or server-error page.

## Copy rules

- Say that the page cannot be found, not that the entire service is unavailable.
- Suggest checking the address only as one possibility; do not blame the visitor.
- Provide at least one clear route back to a useful area.
- Do not claim to have searched the site or discovered related results.
- Avoid jokes that obscure the error or make recovery harder.

## Constraints

- Static, self-contained HTML with embedded CSS and no external assets required to render.
- No JavaScript, live search, URL parsing, redirects, analytics, or auto-refresh.
- All links are placeholders, and all content is hard-coded.
- Do not state that the page, company, or event is fictional.

---

# 429 Rate Limited Page

Specification for a **static, self-contained rate-limit page** for an online software platform or API. The page explains that too many requests were made in a short period and gives measured retry guidance without a live timer.

## Core

### Full

```
Generate a static, self-contained HTML/CSS page for an online software platform's 429 Too Many Requests response. It explains that a request limit has been reached for an account, API key, IP address, workspace, or feature. It may show a static retry interval or reset timestamp, identify the affected limit, and provide support and documentation links.

The page is essentially a static HTML document. Branding, the error message, limit metadata, retry guidance, and footer are hard-coded rather than read from live headers or an account system. There is no scripting to count down, retry requests, inspect usage, or refresh the page. Links are placeholders, and updating the content requires editing the HTML directly.

Make a deterministic choice and include only a subset of the elements below. Fabricate realistic details where needed, but do not state that the page or its contents are fictional. Choose either a compact throttle notice or a fuller page with limit metadata and integration guidance.

- **Branding and presentation:** organization name, product name, logo, navigation labels, layout, and visual styling.
- **Error identification:** 429 status code, Too Many Requests or Rate Limited title, and request ID.
- **Limit scope:** account, workspace, API key, IP address, endpoint group, or feature, without exposing private identifiers.
- **Retry guidance:** a static retry interval, an absolute reset timestamp with timezone, or a recommendation to wait briefly and retry once.
- **Usage context:** requests allowed per window, current limit state, or plan-level note, presented only as frozen example content.
- **Integration guidance:** exponential backoff, jitter, honoring Retry-After, reducing concurrency, and avoiding immediate repeated retries.
- **Support options:** documentation, request ID, plan or limit-increase contact, and support links.
- **Footer content:** copyright, policy links, support links, and additional resources.

Do not include a live countdown, automatic retry, or copy that becomes misleading as time passes. If an absolute reset time is included, label it clearly and include a last-reviewed line.
```

### Minimized

```
Generate a static, self-contained HTML/CSS 429 Too Many Requests page for an online software platform or API.

Core content (hard-coded, no live data):

    Branding: organization or product name
    Error: 429, rate-limit title, one-sentence explanation
    Guidance: wait before retrying; avoid repeated immediate requests
    Footer: documentation or support link and copyright

Constraints:

    No JavaScript, countdown, automatic retry, usage lookup, or auto-refresh
    All content hard-coded; links are placeholders
    Do not display a timer that appears to update
    Do not mention that the page is fictional or fabricated

Include only a subset of the optional content. Make it minimalistic.
```

## Styling

### Page-level layouts (pick one)

1. **Metered notice** — compact title above a static segmented limit bar and retry guidance.
2. **API response sheet** — monospace request metadata in a bordered block with a plain-language explanation beneath.
3. **Split limit panel** — large `429` on the left and limit scope, retry guidance, and support on the right.
4. **Rate-ruler layout** — horizontal tick marks representing a fixed request window, with no moving indicator.
5. **Centered quiet card** — short message, one static retry line, and one documentation link.

### Shape devices

- Use a row of request marks with a subset muted to suggest a fixed allowance.
- Use a static bucket, gauge, or segmented meter without implying live measurement.
- Present limit metadata as hairline-separated definition rows.
- Use a pause or spacing motif rather than a failure symbol.

## Copy rules

- Explain that the limit is temporary and related to request frequency, not data loss.
- Give one unambiguous retry instruction and discourage rapid repeated attempts.
- Distinguish a static retry suggestion from a live countdown.
- For API audiences, mention honoring `Retry-After` and using backoff only if those details fit the page.
- Avoid threatening language and do not imply wrongdoing.

## Constraints

- Static, self-contained HTML with embedded CSS and no external assets required to render.
- No JavaScript, countdowns, request retries, usage lookups, or auto-refresh.
- All links are placeholders, and all content is hard-coded.
- Do not state that the page, company, or event is fictional.

---

# 500 Internal Server Error Page

Specification for a **static, self-contained internal-server-error page** for an online software platform. The page acknowledges an unexpected server-side failure and provides a concise recovery path without exposing diagnostics.

## Core

### Full

```
Generate a static, self-contained HTML/CSS page for an online software platform's 500 Internal Server Error response. It explains that the request could not be completed because of an unexpected server-side problem. It may include a static request ID, a timestamp, a status-page link, and brief retry or support guidance.

The page is essentially a static HTML document. Branding, navigation, the error summary, request metadata, guidance, and footer are hard-coded rather than retrieved from logs or a monitoring system. There is no scripting to retry the request, collect diagnostics, report the error, or refresh the page. Links are placeholders, and updating the content requires editing the HTML directly.

Make a deterministic choice and include only a subset of the elements below. Fabricate realistic details where needed, but do not state that the page or its contents are fictional. Choose either a compact error notice or a fuller page with request metadata and next steps.

- **Branding and presentation:** organization name, product name, logo, navigation labels, layout, and visual styling.
- **Error identification:** 500 status code, Internal Server Error title, and a concise plain-language summary.
- **Request metadata:** request ID, static timestamp with timezone, and optional product area.
- **Customer guidance:** retry once later, return to a stable area, avoid repeating a non-idempotent operation, or contact support if the problem persists.
- **Service context:** optional status-page placeholder link and a note that the page itself does not reflect live service health.
- **Support details:** request ID to quote and a short list of useful details to include in a report.
- **Footer content:** copyright, policy links, support links, and additional resources.

Do not expose stack traces, source paths, environment variables, database errors, queries, secrets, or internal hostnames. Do not claim that engineers have been notified unless that statement is explicitly part of the hard-coded page copy.
```

### Minimized

```
Generate a static, self-contained HTML/CSS 500 Internal Server Error page for an online software platform.

Core content (hard-coded, no live data):

    Branding: organization or product name
    Error: 500, Internal Server Error title, one-sentence explanation
    Metadata: optional static request ID
    Action: retry later or contact support
    Footer: support link and copyright

Constraints:

    No JavaScript, retries, diagnostics collection, reporting, or auto-refresh
    All content hard-coded; links are placeholders
    Do not expose stack traces or internal technical details
    Do not mention that the page is fictional or fabricated

Include only a subset of the optional content. Make it minimalistic.
```

## Styling

### Page-level layouts (pick one)

1. **Diagnostic ticket** — request ID in a monospace stub with a concise error summary and next step.
2. **Centered failure card** — large status code, restrained explanation, and support link.
3. **Split traceback abstraction** — geometric interrupted lines on one side, safe public metadata on the other; never show a real trace.
4. **Memo layout** — brand header, timestamped notice, definition rows, and a sparse footer.
5. **System-console block** — a few generic public-facing lines such as `status: 500` and `request: REQ-…`, with no internal details.

### Shape devices

- Use interrupted circuitry, a disconnected module, or a stopped process line as an abstract motif.
- Use border weight to distinguish the primary error block from secondary guidance.
- Present request metadata in monospace, separated by hairlines.
- Use one subdued warning accent; avoid flashing lights and aggressive alarm styling.

## Copy rules

- Acknowledge that the request failed and that the problem is server-side.
- Keep the explanation understandable without hiding the 500 classification.
- Do not speculate about a cause, resolution time, or monitoring state.
- Warn against repeating purchases, submissions, or other non-idempotent actions when relevant.
- Put the request ID near the support instruction so it is easy to quote.

## Constraints

- Static, self-contained HTML with embedded CSS and no external assets required to render.
- No JavaScript, retries, telemetry, error reporting, diagnostics collection, or auto-refresh.
- All links are placeholders, and all content is hard-coded.
- Never include private logs, stack traces, credentials, or infrastructure details.
- Do not state that the page, company, or event is fictional.

---

# 502 Bad Gateway Page

Specification for a **static, self-contained bad-gateway page** for an online software platform. The page explains that a gateway or edge service received an invalid or unavailable upstream response and offers restrained next steps.

## Core

### Full

```
Generate a static, self-contained HTML/CSS page for an online software platform's 502 Bad Gateway response. It explains in plain language that an intermediary service could not obtain a valid response from an upstream service. It may include a static request ID, edge or region metadata, a timestamp, retry guidance, and status and support links.

The page is essentially a static HTML document. Branding, the gateway error, request metadata, guidance, and footer are hard-coded rather than obtained from a proxy, load balancer, or monitoring system. There is no scripting to retry the request, select another region, test upstream health, or refresh the page. Links are placeholders, and updating the content requires editing the HTML directly.

Make a deterministic choice and include only a subset of the elements below. Fabricate realistic details where needed, but do not state that the page or its contents are fictional. Choose either a compact gateway notice or a fuller page with request metadata and service guidance.

- **Branding and presentation:** organization name, product name, logo, navigation labels, layout, and visual styling.
- **Error identification:** 502 status code, Bad Gateway title, and a concise plain-language explanation.
- **Request metadata:** request ID, static timestamp with timezone, and optional public-facing region label.
- **Gateway context:** a simple browser-to-gateway-to-service path with the final connection marked unavailable.
- **Customer guidance:** retry once after a short wait, return to the product home page, or check the status page.
- **Service context:** optional note that some platform areas may remain available, without claiming live health information.
- **Support details:** request ID to quote, support contact, and what to include if the problem persists.
- **Footer content:** copyright, policy links, support links, and additional resources.

Do not expose upstream hostnames, IP addresses, proxy configuration, provider-specific diagnostics, or internal topology. Do not imply that the page has tested the gateway or upstream service.
```

### Minimized

```
Generate a static, self-contained HTML/CSS 502 Bad Gateway page for an online software platform.

Core content (hard-coded, no live data):

    Branding: organization or product name
    Error: 502, Bad Gateway title, one-sentence explanation
    Metadata: optional request ID and static timestamp
    Action: retry later or visit the status page
    Footer: support link and copyright

Constraints:

    No JavaScript, retries, health checks, region detection, or auto-refresh
    All content hard-coded; links are placeholders
    Do not expose proxy or upstream infrastructure details
    Do not mention that the page is fictional or fabricated

Include only a subset of the optional content. Make it minimalistic.
```

## Styling

### Page-level layouts (pick one)

1. **Broken connection diagram** — three nodes labeled Browser, Gateway, and Service with a static break before the final node.
2. **Edge-response ticket** — status code, request ID, region, and timestamp in compact metadata rows.
3. **Centered gateway card** — plain-language explanation with one retry instruction and one status link.
4. **Split route layout** — large `502` and title on the left, simplified request path and guidance on the right.
5. **Network letterhead** — minimal brand header, monospace metadata, short body copy, and footer.

### Shape devices

- Use two connected line segments and one disconnected segment to represent the failed upstream hop.
- Use a gateway arch, paired brackets, or interrupted bridge as a simple geometric anchor.
- Keep request-path labels generic and public-facing.
- Use dashed borders to distinguish the unavailable hop without animation.

## Copy rules

- Explain that a gateway received no valid upstream response; avoid blaming the visitor's device or connection.
- Keep technical detail proportional to the audience and provide a plain-language summary first.
- Suggest a later retry, but do not imply that a retry is happening automatically.
- Do not invent an affected region, recovery estimate, or live service state beyond the chosen static content.
- Place the request ID beside the support guidance.

## Constraints

- Static, self-contained HTML with embedded CSS and no external assets required to render.
- No JavaScript, retries, health checks, network detection, region selection, or auto-refresh.
- All links are placeholders, and all content is hard-coded.
- Never expose internal addresses, proxy configuration, or upstream diagnostics.
- Do not state that the page, company, or event is fictional.
