# Portal Page - Prompt Instructions

Specification for generating a **static sign-in page** - a portal that presents a username/password form for a believable internal service. The form posts the credentials back to the same URL for the operator to review.

---

## Core

### Full

```
Generate a static, self-contained HTML page that presents a sign-in form for a believable internal product - a webmail portal, VPN gateway, file server, HR self-service, or admin console. It must look like the product's real entry point: focused, calm, and unremarkable.

The page is a **static HTML document** with one form. The form POSTs the credentials to the SAME URL the page was served from (action="" or the current path). The operator reviews submissions in the control plane. Do not mention that the page is generated, staged, or that credentials are collected.

MANDATORY form contract:
  - <form method="post"> with NO absolute action (posts back to the same URL)
  - field names exactly: username, password
  - an optional third field is allowed (domain, otp) only if the scenario calls for it

Pick and choose elements (DO NOT INCLUDE ALL OF THE BELOW):
- **Scenario:** webmail, VPN gateway, file server, HR portal, intranet console, customer billing portal.
- **Branding:** generic product/organization name, small mark, footer.
- **The form:** username + password, a sign-in button, optional "remember me".
- **Support copy:** "forgot password?" placeholder link, a helpdesk line.
- **Context lines:** "authorized users only", a login-notice/consent line (common on internal tools).
- **Footer:** copyright, policy placeholders.
```

### Minimized

```
Generate a minimal, self-contained sign-in page for a believable internal product (webmail, VPN, file server). Generic branding, a form that POSTs username+password back to the same URL (no absolute action), a sign-in button, and a small footer. No external assets, no JavaScript required, no mention of generation. Keep it quiet and ordinary.
```

---

## The form contract (mandatory)

- The form posts to the same URL: `<form method="post">` with no absolute action attribute.
- Field names are exactly `username` and `password`. A wrong name loses the capture.
- No client-side validation that blocks submission; no CAPTCHA, no MFA interstitial - the first POST is the capture.
- After submission the server decides what the visitor sees - the page itself never shows success or failure.

## Scenario layouts (pick one)

1. **Centered login card** - product mark, two fields, button, small links. The universal default.
2. **Split hero** - left column with product name + marketing line, right column with the form.
3. **Gateway band** - a thin header with the product name, a compact centered form, a consent line below. VPN feel.
4. **Document style** - letterhead top, form as a bordered block, notices beneath. For HR/compliance portals.
5. **Terminal-adjacent** - monospace labels, flat inputs, zero decoration. For admin consoles.

## Trust devices worth mixing in

- **A consent/notice line** - "Authorized access only. Activity may be monitored." Common on real internal tools.
- **Version/build footer** - "v4.2.1 (build 1187)" in small print.
- **A small logo block** - colored square + wordmark.
- **"Remember me"** or a language selector for realism.

## Constraints

- One file, self-contained, no external assets.
- No JavaScript requirement - the form works without it.
- Neutral product palette; the sign-in button is the only loud element.
- No real trademarks unless the operator supplies them.
