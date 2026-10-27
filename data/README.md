# ./data/ - operator content

Everything the operator creates or uploads lives here:

| Path | Contents |
|---|---|
| `payloads/` | the payload library (one folder per bundle) |
| `loading/` | custom "loading" held-view pages |
| `fingerprint/` | custom fingerprint held-view pages |
| `download/` | custom after-download interstitials |
| `benevolent/` | custom deny-response pages |
| `media/` | uploaded payloads, deny files, extracted images |
| `robots.txt`, `sitemap.xml` | surface-document overrides (optional) |

Only the shipped `example.*` samples and `payloads/example-bundle/` are
tracked in git. Your own files stay local and are never committed or pushed.
