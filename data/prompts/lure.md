# Lure Page - Prompt Instructions

Specification for generating a **static bait page** that leads a visitor to download a file. The page presents a believable reason for the file and a prominent download path. The download target is a placeholder the operator wires to the real link afterwards.

---

## Core

### Full

```
Generate a static, self-contained HTML page that presents a file download as a normal part of a believable scenario. The page is a **download/bait page** - a document portal, invoice viewer, update notice, shared-file landing, or similar - that gives the visitor a reason to download and a button to do it.

The page is a **static HTML document**. No live data, no scripting required beyond an optional direct-download click. Branding, file metadata, and copy are hard-coded and internally consistent. Do not mention the page is generated, staged, or simulated - and never include words like "sample", "test", or "demo".

MANDATORY: the download control's target is written exactly as the placeholder %PAYLOAD_URL% - the operator substitutes the real delivery URL when deploying. Every path that starts the download must use it.

Pick and choose elements (DO NOT INCLUDE ALL OF THE BELOW):
- **Scenario:** shared document portal, invoice/statement viewer, software update notice, secure file transfer, voicemail attachment, fax-to-email, e-signature request, compliance notice.
- **Branding:** a generic-sounding organization or product name, logo mark, footer links. Avoid real trademarks unless the operator supplies them.
- **The file card:** filename, size, type icon, upload date (absolute, near today), maybe a "scanned clean" line.
- **Urgency without alarm:** "available until <date>", "action required by <date>", "review requested" - never threats.
- **Trust signals:** a reference ID, a sender name + role, a department, a confidentiality line.
- **The action:** one primary download button; optionally a secondary "view online" link to the same placeholder.
- **Footer:** privacy/terms placeholders, copyright.
```

### Minimized

```
Generate a minimal, self-contained download page for a believable scenario (shared document, invoice, update). Hard-code generic branding, a file card (name, size, type, date close to today), one primary download button pointing at the placeholder %PAYLOAD_URL%, and a small footer. No JavaScript required, no live data, no countdowns, no fake-page admissions. Keep it minimalistic and fast.
```

---

## The download placeholder (mandatory)

- Every download path uses `%PAYLOAD_URL%` verbatim - button href, direct link, any JS fallback.
- The page never hosts the file itself; it only points at it.
- If the page offers a "copy link" affordance, the copied text is `%PAYLOAD_URL%`.

## Scenario layouts (pick one)

1. **File card portal** - centered card: file icon, name, size, date, big download button. The classic shared-file landing.
2. **Document viewer shell** - a fake preview area (grey page outline or blurred placeholder lines) with a download bar on top. "Preview unavailable - download to view."
3. **Invoice/statement page** - letterhead block, amount and reference lines, download row at the bottom.
4. **Update notice** - version line, short "what's new" bullets, size, download button. For software-update scenarios.
5. **Voicemail/fax attachment** - transcript placeholder lines, duration, "download the recording/document".
6. **E-signature request** - sender, document, a "review and sign" button plus "download copy".

## Trust devices worth mixing in

- **Reference ID** in monospace, oversized or in a ticket stub.
- **File metadata table** - two-column hairline rows (name, size, type, uploaded, expires).
- **"Scanned" line** - one calm sentence; no fake vendor names unless the operator supplies them.
- **Sender block** - name, role, department, small avatar-colored initial circle.
- **Availability window** - absolute dates only ("Available until 2026-11-02"), never relative countdowns.

## Constraints

- One file, self-contained, no external assets or fonts.
- Dates are absolute and close to today; nothing relative ("in 3 days").
- The tone is routine business - calm, boring, slightly administrative.
- The download button is the only visually loud element on the page.
