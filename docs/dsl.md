# DSL Reference

Configuration languages used across the control plane: submission ciphers,
auto-decision rules, and link templates.

## Submission cipher templates

Used by `gate_type=submission` links to decode/decrypt the POST body.
The body may be the raw blob or a JSON wrapper: `{"data": "<blob>"}`.

| Template | Key | IV | Decodes to |
|---|---|---|---|
| `base64` | - | - | raw bytes (must be JSON) |
| `xor` | passphrase | - | base64(blob) XOR key bytes (repeating) |
| `aes256` | 32-byte hex, or passphrase (→ SHA-256) | 16-byte hex | AES-256-CBC, PKCS7 |

After decoding, the payload must be a JSON **object** and contain every field
in `expected_fields`. String fields that base64-decode to image magic bytes
(PNG/JPEG/GIF/BMP) are extracted as images.

## Auto-decision rules (`auto_rules`)

```json
[
  {"action": "approve",
   "when": {"fields_match": {"hostname": "^corp-laptop-\\d+$"},
            "forbid": ["vmware|virtualbox", "sandbox"],
            "require_images": true}},
  {"action": "deny",
   "when": {"fields_match": {"hostname": "^sandbox"}}}
]
```

Evaluation is top-down; the first rule whose `when` matches decides the
submission. No match → stays pending for a human.

- `fields_match` - **all** listed fields must exist and match their regex.
- `forbid` - if **any** decoded value matches **any** forbid regex, the rule
  is skipped. Forbidden signals veto approvals; they cannot trigger denies by
  themselves (write an explicit deny rule for patterns you want dead).
- `require_images` - at least one image must have been extracted.

Every auto-decision records `via: auto-rule#<index>` and the matched reasons in
the HitEvent detail.

## Gate types

> TOTP codes are single-use per link: the first accepted code is recorded,
> a replay is rejected and logged as a suspicious event, and records prune
> after three windows. The code format (8-hex truncated HMAC vs 6-digit
> decimal) is an operator setting under Settings -> Gate codes.

| Gate | Client presents | Failure response |
|---|---|---|
| `none` | path only | hold response |
| `token` | `?t=` or `X-Gate-Token` header | hold response + suspicious event |
| `totp` | time-based code (`?t=` or header), single-use per link | hold response + suspicious event |
| `submission` | POST body (cipher template) | hold response; undecryptable → suspicious |

Fingerprint requirements (JA3/JA4) compose with the gate type: the gate must
pass **and** the fingerprint must match.

Hold responses: `blank` (HTTP 204), `placeholder` (generic page), `decoy`
(convincing default page with canary pixel).

## Deployment templates

Built-in presets (`gates/link_templates.py`), loadable from the link form:

| Template | Use |
|---|---|
| `dropper-checkin` | AES-encrypted env package; approval before key release; benevolent fallback |
| `key-drop-one-time` | TOTP-gated, single-retrieval key, time-limited |
| `loader-stage` | Token-gated file with benevolent fallback, limited uses |
| `file-drop` | pwndrop proxy, 10 uses, watermarking on |

`{placeholder}` values in defaults are meant to be replaced at creation.
