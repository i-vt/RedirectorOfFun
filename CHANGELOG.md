# Changelog

## v1.1.0 - 2026-10-27

The operator-experience release: payload management, hosted lures, guided UI,
per-visitor admissions, and a hardening audit. 448 tests, CI green.

### Delivery and payloads

- Quick drop: one file, one click, a live URL (with QR code) from the Links
  page or a phone.
- Payloads page: a file manager for payloads, benevolent fallbacks, and
  decoys, with gate intel per link and in-place payload replacement.
- Payload library at ./data/payloads/: bundle folders with notes (markdown,
  shown as escaped text) and generated favicons; pick library files directly
  when creating a link or building a lure.
- Per-link download charts, drag-and-drop uploads, and serve-as filename
  masquerade (store fwfafs.exe, serve helper.pdf.exe).
- Serve ratios (1/20 style probabilistic serving) and a post-download
  interstitial that redirects visitors to a stable, per-link benevolent page.

### Gates

- New network gate: IP / User-Agent allow-lists with no credentials at all.
- Malleable header contracts, replay dedupe, daily availability windows,
  JA3/JA4 pins, domain pinning (now enforced), and per-visitor operator
  admission with sticky TTL.
- Loading and fingerprint held pages: neutral auto-retry pages, and an
  intel-collecting check page that feeds the operator before the decision.
- Custom held/download/deny pages from pools under ./data/.
- Auto-decision learning: remember a decision once and matching submissions
  decide themselves (panel, mobile, API, Telegram).

### Interface

- Guided everywhere: per-page help modals, field tooltips, collapsed advanced
  sections, a Ctrl+K command palette, a scrollable sidebar, live-refreshing
  approval queues, and mobile parity (intel gallery, quick drop, admissions).
- Settings toggle for full vs masked identifiers.

### Operations and hardening

- update.sh (pull, rebuild, prune; --reset for clean installs); ./data/ holds
  all operator content, committed with default samples only.
- robots.txt and sitemap.xml generated on the fly per deployment.
- Track-all-requests mode for the event stream with status-class filters.
- Audit: placeholder 500, replay/approval ordering, proxy-IP ban self-owns,
  creation races, nginx config injection, rate-limit keying, and a dozen
  smaller fixes (see the commit log).

## v1.0.0 - 2026-10-25


First release. RedirectorOfFun started as an nginx C2 redirector fork and now
ships with a full operator control plane.

### Edge (shell + nginx)

- Automated redirector setup/teardown with Let's Encrypt, threat-intel
  blocklists, UA filtering, rate limiting, header stripping, decoy and
  maintenance pages, profiles, log scrubbing, webhook alerts, dry-run/verbose
  modes, and Docker support.
- Per-agent beacon routes and operator-ban include files, managed by the panel.

### Control plane (Django panel)

- Release gates under /g/: key distribution, gated file downloads, pwndrop
  proxying, token/TOTP/submission gates with base64/XOR/AES-256 templates,
  operator approval queue with auto-decision rules, one-time and time-limited
  links, custom paths, per-agent tagging.
- Operator ergonomics: keyboard review (j/k/a/d/u), undo window, submission
  notes, Telegram text and inline-button approvals, browser and Web Push
  notifications, mobile UI at /m/, morning overview metrics.
- Safety: burn notice (deactivate, deny, ban all visitors except the approved
  target), per-release watermarking for leak tracing, decoy canary pixels,
  JA3/JA4 hooks for an OpenResty front layer, domain pinning.
- Firewall-style blocking chain: rulesets with everything/404s/link scopes,
  typed regex and CIDR conditions, ALL/ANY/NONE logic with negation, ALLOW
  rules that override later blocks, drag-and-drop ordering, JSON export/import,
  presets for VirusTotal/cloud-ASN/scanner traffic, and a dry-run test page.
- Decoy page management: built-in pages, uploads, redirects, single default
  applied to 404s, denials, and bans.
- Security: one-time capability bootstrap, TOTP 2FA with backup codes,
  invitations, API keys (hashed at rest, per-operator, revocable), a secret
  per-deployment URL prefix for every operator path, IP allowlisting as an
  opt-in, and X-Forwarded-For trust controls.
- Telemetry: 404 ingestion from nginx JSON logs with raw IP/user-agent
  identifiers, per-row detail views, identifier filters, gate HitEvents with
  hashed dashboards, audit trail for every operator action.
- Themes: Default, Cozy Clown, and Obnoxious Clown per account, with themed
  favicons and the star-tipped jester brand mark.

### Tooling

- 235-test unit/functional suite, Docker-contained browser e2e stack, CI with
  Django checks + tests + strict selftest, shellcheck, and compose validation.
- start.sh: one-command deploy, --reset (volume-safe teardown), --no-cache
  builds, per-interface access URLs, preflight checks for password/volume
  mismatches and port conflicts.
- MIT license.
