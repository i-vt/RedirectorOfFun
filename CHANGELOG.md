# Changelog

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
