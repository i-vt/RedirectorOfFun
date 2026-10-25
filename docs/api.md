# API Reference

REST API under `/api/v1/` (behind the operator prefix in production). Two
credential types:

- Session cookie from `/login/` (+ `/login/totp/` when 2FA is enabled)
- API keys: `Authorization: ApiKey rofk_<secret>` (CSRF-free; the key acts as
  its owner with the owner's roles, is hashed at rest, shown once, revocable)

Anonymous requests are rejected. Create keys on the Security page, via
`POST /api/v1/apikeys/`, or `manage.py create_apikey <username>`.

## API keys

| Method | Path | Purpose |
|---|---|---|
| GET/POST | `apikeys/` | List your keys (admins can `?all=1`) / provision (full key returned once) |
| POST | `apikeys/<id>/revoke/` | Revoke (own keys; admins any) |

## Links

| Method | Path | Purpose |
|---|---|---|
| GET/POST | `links/` | List / create delivery links |
| GET/PATCH/DELETE | `links/<id>/` | Read / update / delete |
| POST | `links/<id>/burn/` | Burn notice: deactivate + ban visitor IPs |

Writable fields include `path`, `kind`, `key_text`, `pwndrop_url`, `gate_type`,
`gate_token`, `totp_secret`, `totp_window`, `cipher`, `cipher_key`, `cipher_iv`,
`expected_fields`, `auto_rules`, `placeholder`, `on_deny`,
`requires_approval`, `one_time`, `max_uses`, `expires_at`, `active`, `domain`,
`ja3_fingerprint`, `ja4_fingerprint`, `watermark`, `payload`, `benevolent_file`.

`payload` and `benevolent_file` are file fields: send them as multipart form data
when writing; reads return the file URL (or `null`). Responses also include a
read-only `payload_size` in bytes (`null` when no payload is attached or the
file is missing from storage).

## Submissions

| Method | Path | Purpose |
|---|---|---|
| GET | `submissions/?status=pending` | Approval queue |
| POST | `submissions/<id>/approve/` `…/deny/` | Decide (409 if already decided) |
| POST | `submissions/<id>/undo/` | Revert within the undo window |
| POST | `submissions/<id>/note/` | Body: `{"note": "..."}` |

## Bans, agents, telemetry

| Method | Path | Purpose |
|---|---|---|
| GET/POST | `bans/` | List / create (`{"ip", "note"}`) |
| GET/PATCH | `bans/<id>/` | Read / enable / disable |
| GET/POST | `agents/` | Per-agent C2 channels |
| GET/PATCH/DELETE | `agents/<id>/` | Manage channel |
| POST | `agents/<id>/rotate/` | New token (burns deployed agent) |
| GET | `hit-events/?category=suspicious` | Surface telemetry (cursor-paginated) |
| GET | `gate-stats/` | 24h aggregates + pending counts |

## Lures (hosted multi-page sites)

Lures are served publicly at `<LURE_BASE_PATH><slug>/<file>` (default `/l/`).

| Method | Path | Purpose |
|---|---|---|
| GET/POST | `lures/` | List / create sites (`{"name", "slug", "description", "active"}`) |
| GET/PATCH/DELETE | `lures/<id>/` | Manage a site (responses include nested `files` and `public_path`) |
| PUT | `lures/<id>/file/` | Upsert a file: `{"path": "index.html", "content": "..."}` |
| DELETE | `lures/<id>/file/` | Remove a file: `{"path": "index.html"}` |

## Decoys

| Method | Path | Purpose |
|---|---|---|
| GET/POST | `decoys/` | List / create decoy pages |
| GET/PATCH/DELETE | `decoys/<id>/` | Manage (writable `html` overrides the source content; `assets` nested read) |
| POST | `decoys/<id>/default/` | Make the default cover page |
| PUT | `decoys/<id>/asset/` | Upsert a tied asset: `{"path": "style.css", "content": "..."}` |
| DELETE | `decoys/<id>/asset/` | Remove an asset: `{"path": "style.css"}` |

Decoy assets are served publicly at `/d/<page id>/<path>` so the decoy HTML can
reference its own CSS/JS from any 404 context.

## Blocking rules

| Method | Path | Purpose |
|---|---|---|
| GET/POST | `block-rules/` | List / create rules |
| GET/PATCH/DELETE | `block-rules/<id>/` | Read / update / delete (presets cannot be deleted) |
| GET/POST | `block-rules/sets/` | List / create rulesets |
| GET/PATCH/DELETE | `block-rules/sets/<id>/` | Manage a ruleset (deleting orphans its rules into the ungrouped chain) |
| POST | `block-rules/reorder/` | `{"kind": "rule"|"set", "ids": [...]}` rewrites ordering |
| GET | `block-rules/export/` | Download the full chain as JSON |
| POST | `block-rules/import/` | Import a JSON export (lands disabled, `(imported)` suffix on collisions) |
| POST | `block-rules/test/` | Dry-run `{"ip", "ua"}` against every rule |

## Web Push

| Method | Path | Purpose |
|---|---|---|
| GET | `push/key/` | VAPID public key + configured flag |
| POST | `push/subscribe/` | Body: PushSubscription JSON (`endpoint`, `keys`) |
| POST | `push/unsubscribe/` | Body: `{"endpoint"}` |

## Operators, system

| Method | Path | Purpose |
|---|---|---|
| GET | `operators/` | List operators (admin) |
| POST | `operators/invitations/` | Create an invitation, returns the acceptance URL (admin) |
| POST | `operators/<id>/revoke/` | Deactivate an operator (admin) |
| POST | `operators/<id>/reset-2fa/` | Clear their 2FA and invalidate sessions (admin) |
| GET | `links/<id>/totp/` | Current TOTP codes for a time-gated link |
| POST | `selftest/` | Run the startup check suite on demand |

## Existing endpoints

`404-events/`, `404-stats/`, `audit-events/`, `notification-preferences/`,
`notifications/recent/?after=<id>`.

## Errors

- `400` - validation (malformed auto-rules, bad IP, path outside the gate base)
- `401/403` - unauthenticated / insufficient role
- `409` - conflicting state (already decided, undo expired)
- `410` - expired link hit (public surface)
