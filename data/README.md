# ./data/ - operator content

Everything the operator creates or uploads lives here:

| Path | Contents |
|---|---|
| `payloads/` | the payload library (one folder per bundle) |
| `loading/` | custom "loading" held-view pages |
| `fingerprint/` | custom fingerprint held-view pages |
| `download/` | custom after-download interstitials |
| `benevolent/` | custom deny-response pages |
| `prompts/` | AI prompt specs for generating content (operator-local) |
| `decoys/` | decoy pages pool (pick them when adding a decoy) |
| `media/` | uploaded payloads, deny files, extracted images |
| `robots.txt`, `sitemap.xml` | surface-document overrides (optional) |

Only the shipped samples (`example.*`, `payloads/example-bundle/`, and
the three `decoys/` pages) are tracked in git. `prompts/` is never tracked. Your own files stay local and are never committed or pushed.
