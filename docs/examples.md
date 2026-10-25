# Example rules and rulesets

Ready-made chains in `samples/` — import them from Blocking Rules (Import
Rules) or with `POST /api/v1/block-rules/import/`. Everything lands disabled;
review on the Test page before enabling.

## scanner-defense.json

One "everything" set with three block rules: VirusTotal egress (UA contains
`virustotal`), AWS cloud scanners (ASN is `16509`/`14618` AND the UA looks
like a bot/script), and scripting user agents (`curl`/`wget`/python-requests/
go-http-client at the start). Straight out of the VirusTotal triage workflow.

## allow-soc-block-rest.json

The chain-ordering demo: an ALLOW rule for the SOC laptop's IP first, then a
BLOCK for everyone (`ua is anything`). First match wins, so the operator
passes and the rest of the internet gets the decoy.

## 404-probes-only.json

A ruleset scoped to **404s only**: known scanner fingerprints get blocked on
probe paths, and a second rule blocks non-browser UAs from non-loopback
addresses (the `^(?!...)$` negative-lookahead pattern is how "does not
contain Mozilla" is written as a regex). Gate links keep working normally.

## single-link-guard.json

A ruleset scoped to **one delivery link** (`/g/drop/example` - edit the path
to yours): block anyone whose ASN is not the customer's (the negative
lookahead against the ASN), plus a loose rule blocking VirusTotal anywhere.

## Quick rule generator

On the Blocking Rules page, "Quick rule generator" opens a question-driven
builder: each row asks what to check (IP, CIDR, UA, ASN, ISP, country, city),
how to compare (starts with / contains / is / is not / doesn't contain /
ends with / is anything / is not empty / is empty), and the value. The
combiner offers AND, OR, and XOR (exactly one matches). The live preview
shows the generated regex and the final JSON; Create writes the rule into the
form and submits it for you.

Operator-to-regex mapping used by the builder:

| Question | Regex |
|---|---|
| starts with `x` | `^x` |
| contains `x` | `x` |
| is `x` | `^x$` |
| is not `x` | `^x$` + negate |
| doesn't contain `x` | `x` + negate |
| ends with `x` | `x$` |
| is anything | `.*` |
| is not empty | `.+` |
| is empty | `^$` |

Values are regex-escaped automatically; CIDR conditions only offer is/is-not
(network membership instead of regex).
