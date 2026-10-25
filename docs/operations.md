# Operations Guide

Daily operation of the RedirectorOfFun control plane: gates, approvals, and
incident response. Read `deploy.md` for installation.

## The morning loop

1. Open `/panel/` - the gate strip shows pending approvals, releases in the
   last 24h, and suspicious events.
2. Work the approval queue at `/panel/submissions/`:
   - `j` / `k` move between submissions, `a` approve, `d` deny, `u` undo
     (within `DECISION_UNDO_SECONDS`, before any release).
   - Expand a row to see decoded JSON, extracted screenshots, and add an
     operator note (notes are shared between operators and visible on mobile).
3. Phone-only? Use `/m/` (mobile UI) or reply to the Telegram bot:
   `approve 42`, `deny 42`, `pending`. Notifications carry inline buttons.

## Approving safely

- The decoded JSON + screenshot is your evidence. Check hostname against the
  customer's naming convention, look for VM artifacts, timezone mismatches.
- `forbid` patterns in auto-rules are the safety net; a rule never fires when a
  forbidden value is present anywhere in the submission.
- Deny sends whatever the link's `on_deny` says: 404, decoy, or your
  benevolent response. Configure `benevolent_text` / `benevolent_file` per link
  *before* the engagement.

## Releasing

After approval the next visit to the link serves the content and starts the
download automatically. One-time links die after their first release; watch
the `download` / `key_served` events for the confirmation.

With `watermark` enabled, every release carries a unique marker
(`ROFWM:<link>:<use>:<hex>`); the exact value is in the download HitEvent. If
a sample shows up in a sandbox report, grep the marker against your events to
identify which link and release leaked it.

## Incident response: burn notice

When a link is discovered mid-engagement, open its detail page (or mobile
view) and hit **Burn notice**. It:

1. Deactivates the link and flips it to the deny response.
2. Bans every raw IP that hit the link, **except** the approved target's
   address (taken from the approved submission).
3. Rewrites the nginx ban include, records a suspicious event, notifies, and
   writes an audit entry.

Burn is one-way. If you need the link back, clone its configuration manually.

## Decoy canaries

On by default (`DECOY_CANARIES=true`). Every decoy page embeds a unique
per-visitor tracking pixel under `/g/canary/<token>.gif`. A hit on that path
is always a machine: either a sandbox re-analyzing the decoy later (valid
token re-hit) or someone probing token patterns (forgery). Both are recorded
as suspicious events; the response is always a 1x1 GIF so the probe learns
nothing.

## Notification channels

- **Panel**: toast + bing (toggle in the topbar) - works while the panel is open.
- **Browser**: Notification API - panel tab must be open; grant permission on Settings.
- **Web Push**: VAPID push - works when the panel is closed. Configure
  `VAPID_PRIVATE_KEY` / `VAPID_PUBLIC_KEY` / `VAPID_ADMIN_EMAIL`
  (`manage.py vapid_keys` generates keys), then enable "Web Push" on Settings
  per device. Select the "Web Push" channel in the preferences matrix.
- **Telegram**: bot DMs; the only channel that also accepts *inbound*
  decisions (replies and inline buttons).

## Blocking rules

Blocking Rules is a firewall-style chain: rulesets evaluated top to bottom,
first matching rule wins. An ALLOW rule stops the chain (use it for trusted
operators so later block rules never touch them); a BLOCK rule serves the
decoy, logs a `blocked` event, and can auto-ban the IP.

- Rules are typed regex conditions: `ip`, `cidr`, `ua`, `asn`, `isp`,
  `country`, `city`, combined with ALL / ANY / NONE logic plus per-condition
  negation. ASN/ISP/geo conditions only fire when enrichment data exists for
  the address (see deploy.md); a rule with unknown inputs never fires.
- Sets default to one "everything" chain; additional sets can be scoped to
  404s only or to a specific delivery link. Drag rules to reorder them inside
  a set; drag set headers to reorder sets.
- Export/Import as JSON from the page header; imports always land disabled.
- Presets seed disabled on first start. Use the Test page (or
  `POST /api/v1/block-rules/test/`) to dry-run any IP + user agent against the
  whole chain before enabling anything - enabled rules apply to operators too.

## Decoy pages and the public surface

Anything outside the operator prefix (unknown URLs, `/`, `/panel/` when
probed) returns the default decoy page - for anonymous visitors and signed-in
operators alike. Only inside the prefix do operators get the panel's own 404.
Pick the default page under Decoy Pages: any of the pages shipped with the
repo, an uploaded HTML file, or a redirect to another site. Every served decoy
carries a per-visitor canary pixel; a re-hit or a forged token shows up as a
suspicious event.
