# API Reference

Session-authenticated REST API under `/api/v1/`. Authenticate as an operator
via `/login/` (and `/login/totp/` when 2FA is enabled); the session cookie
authenticates all requests. Anonymous requests are rejected.

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
`ja3_fingerprint`, `ja4_fingerprint`, `watermark`.

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

## Web Push

| Method | Path | Purpose |
|---|---|---|
| GET | `push/key/` | VAPID public key + configured flag |
| POST | `push/subscribe/` | Body: PushSubscription JSON (`endpoint`, `keys`) |
| POST | `push/unsubscribe/` | Body: `{"endpoint"}` |

## Existing endpoints

`404-events/`, `404-stats/`, `audit-events/`, `operators/`,
`operators/<id>/revoke/`, `notification-preferences/`,
`notifications/recent/?after=<id>`.

## Errors

- `400` - validation (malformed auto-rules, bad IP, path outside the gate base)
- `401/403` - unauthenticated / insufficient role
- `409` - conflicting state (already decided, undo expired)
- `410` - expired link hit (public surface)
