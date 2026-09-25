# Seeded cross-provider disagreements — phase 02

The premise changed in phase 02: there is no golden state. Each provider's
Terraform (`terraform/<domain>/`) is in sync with that provider's own live
state — `scripts/check_iac_sync.py` certifies that baseline — so the defect
the demo detects is that **the two providers disagree with each other**.
Every finding is a question for a human: which side is right? The
remediation PR then edits the *losing* provider's Terraform, in that
provider's own vocabulary.

`scripts/validate_cross_drift.py --check` asserts the classifier produces
exactly the seven findings below — no more, no fewer.

## Findings

| # | Domain | Field | Akamai | Cloudflare | Severity | Type |
|---|--------|-------|--------|------------|----------|------|
| 1 | online.rbcdemo.ca | `tls.min_version` | `TLSV1_2` | `1.0` | critical | disagreement |
| 2 | www.rbcdemo.ca | `waf.managed_ruleset_enabled` | `enabled` | `enabled: false` | critical | disagreement |
| 3 | api.rbcdemo.ca | `ratelimit.partner_api` | `1000` req/min | `100` req/min | high | disagreement |
| 4 | api.rbcdemo.ca | `cors.allowed_origins` | `{online, www}` | `{online, www, partners}` | high | disagreement |
| 5 | www.rbcdemo.ca | `tls.hsts_max_age` | `86400` | `31536000` | medium | disagreement |
| 6 | assets.rbcdemo.ca | `caching.default_ttl` | `1d` | `14400` | medium | disagreement |
| 7 | online.rbcdemo.ca | `headers.security_static` | `nosniff` | absent | medium | missing_at_cloudflare |

### 1. `tls.min_version` — online.rbcdemo.ca (critical)

Akamai's origin behavior sets `minTlsVersion: TLSV1_2`; Cloudflare's zone
setting is `min_tls_version: "1.0"`. PCI-DSS 4.0 requires TLS 1.2+ on any
channel carrying account data, and the other three domains all agree on
1.2 — a reviewer would almost certainly say **Akamai is right** and the
Cloudflare floor drifted (or was never raised) below the estate standard.
Remediation on the losing side: `terraform/online.rbcdemo.ca/cloudflare/zone-settings.json`
`"min_tls_version": "1.0"` → `"1.2"` (Cloudflare vocabulary, not `TLSV1_2`).

### 2. `waf.managed_ruleset_enabled` — www.rbcdemo.ca (critical)

Akamai's `webApplicationFirewall` behavior is enabled; the Cloudflare
`http_request_firewall_managed` ruleset's "Execute Cloudflare Managed
Ruleset" rule has `enabled: false` — the whole managed WAF layer silently
no-ops on the marketing surface. The estate expects WAF on every public
domain, so a reviewer would probably call **Akamai right** and the toggle
the defect. Remediation: in
`terraform/www.rbcdemo.ca/cloudflare/rulesets.json`, set `enabled: true`
on the "Execute Cloudflare Managed Ruleset" rule.

### 3. `ratelimit.partner_api` — api.rbcdemo.ca (high)

Akamai App Sec rate policy `9101` has `averageThreshold: 1000` req/min;
the Cloudflare `http_ratelimit` rule "Open-banking partner rate" allows
`requests_per_period: 100`. The approved partner limit is 100 — the Akamai
side looks like the out-of-band raise (its own fixture comment cites
EDG-2309), so a reviewer would probably say **Cloudflare is right**.
Remediation: `terraform/api.rbcdemo.ca/akamai/appsec.json`, rate policy
id `9101`, `averageThreshold: 1000` → `100`.

### 4. `cors.allowed_origins` — api.rbcdemo.ca (high)

Akamai's CORS preflight behavior emits
`Access-Control-Allow-Origin: https://online.rbcdemo.ca, https://www.rbcdemo.ca`;
Cloudflare's `http_response_headers_transform` rule "CORS headers" emits a
third origin, `https://partners.rbcdemo.ca`. Credential-bearing cross-origin
access to the API surface grew an origin nothing else references — a
reviewer would probably call **Akamai right** (the extra origin is the
unreviewed change). Remediation: in
`terraform/api.rbcdemo.ca/cloudflare/rulesets.json`, remove
`https://partners.rbcdemo.ca` from the `Access-Control-Allow-Origin` value
of the "CORS headers" rule.

### 5. `tls.hsts_max_age` — www.rbcdemo.ca (medium)

Akamai emits `Strict-Transport-Security: max-age=86400`; Cloudflare's HSTS
transform emits `max-age=31536000; includeSubDomains`. One day vs one year —
and `online`'s Akamai tree already carries `max-age=63072000`, so the
estate's norm is the long posture and www's Akamai rule is the outlier.
A reviewer would probably say **Cloudflare is right**. Remediation:
`terraform/www.rbcdemo.ca/akamai/rules.json`, the `Strict-Transport-Security`
header behavior's `customHeaderValue` → `max-age=31536000; includeSubDomains`.

### 6. `caching.default_ttl` — assets.rbcdemo.ca (medium)

Akamai's default-rule `caching` behavior sets `ttl: "1d"`; Cloudflare's
`browser_cache_ttl` is `14400` (4h). Every other domain agrees on 4h on
both providers, so a reviewer would probably say **Cloudflare is right**
and the Akamai TTL was bumped out-of-band. Remediation:
`terraform/assets.rbcdemo.ca/akamai/rules.json`, `caching.options.ttl`
`"1d"` → `"4h"`.

### 7. `headers.security_static` — online.rbcdemo.ca (medium, migration gap)

Akamai's rule tree sets `X-Content-Type-Options: nosniff` on online
banking; Cloudflare's `http_response_headers_transform` ruleset on that
zone has no `security-headers` rule at all (`allow_absent` — the gap is
the finding, not an error). The migration to Cloudflare never carried the
header over, so a reviewer would call **Akamai right** — the control
exists and its Cloudflare twin was skipped. Remediation: add a
`security-headers` `rewrite` rule to the `http_response_headers_transform`
ruleset in `terraform/online.rbcdemo.ca/cloudflare/rulesets.json`, setting
`X-Content-Type-Options: nosniff` (matching the shape `www` already uses).

## Deliberate suppressions — equivalent but textually different

These are the fields where the two providers render the same semantic value
in different vocabularies. They must NOT produce findings; they are the
evidence that the comparison is semantic, not textual. As reported by the
classifier (`equivalent_but_different`, 27 pairs across the four domains):

- **Boolean renderings** — Akamai `options.enabled: true/false` vs
  Cloudflare `"on"`/`"off"`: `compression.brotli`, `http.http2`,
  `http.http3`, `http.zero_rtt`, `origins.true_client_ip` on every domain,
  and `http.http3` on assets where both sides are off.
- **TLS vocabulary** — Akamai `TLSV1_2`/`DYNAMIC` vs Cloudflare `"1.2"`:
  `tls.min_version` on www, api, and assets (`DYNAMIC` resolves to 1.2 via
  the `tls_min_version` value table).
- **Duration renderings** — Akamai `"4h"` vs Cloudflare `14400` seconds:
  `caching.default_ttl` on www, online, and api.
- **Cache-key vocabulary** — Akamai `EXCLUDE_ALL` vs Cloudflare's empty
  `include` list `[]`: `cachekey.strategy_online` on online.
- **Provider defaults** — a Cloudflare setting omitted from the
  zone-settings response (e.g. assets' `http2`) is supplied from
  `defaults.cloudflare_settings` and counts as present at its default —
  no missing finding.

The remaining ~131 provider/field pairs classify as `not_comparable`: the
field exists on only one provider (`unsupported: true` — Akamai-only appsec
controls, Cloudflare-only zone settings) or configures nothing on either
side. That count is informational, not a finding.
