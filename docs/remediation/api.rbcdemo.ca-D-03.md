# Remediation record — api.rbcdemo.ca — D-03 (`ratelimit.partner_api`)

Golden SHA compared: `0a6300de7c7ebd6ee23e7f5cdf6f5f2e9dc735a02167ec576cd5c550a46bb352`

No golden edit was required: golden already holds the intended value. Remediation
is the pipeline re-applying the existing golden tree for `api.rbcdemo.ca` on
merge. This record is what the reviewer signs off on.

## D-03 — `ratelimit.partner_api` (akamai, severity high)

| | |
| --- | --- |
| Golden value | `averageThreshold: 100` (per 60s period, burst 50, action `deny`) |
| Golden path | `golden/api.rbcdemo.ca/appsec/security-config.json` → `$.ratePolicies.items[?(@.id==9101)].averageThreshold` |
| Live (drifted) value | `averageThreshold: 1000` (per 60s period, burst 50, action `deny`) |
| Live location | Akamai appsec config `90012` v9, rate policy `9101` "Open-banking partner rate", `matchType` PATH `/open-banking/*` |
| Terraform resource | `akamai_appsec_rate_policy.api_partner` in `golden/api.rbcdemo.ca/main.tf` |

The policy still exists, still matches `/open-banking/*` and still denies; only the
sustained ceiling drifted, from 100 to 1000 requests per 60s — a 10x loosening of
the only throttle on partner traffic at the Akamai edge. Burst threshold (50) and
period (60s) are unchanged. Both sides express requests per the same 60s period,
so this is a numeric difference, not a units or vocabulary mismatch. Cloudflare's
equivalent rule (`http_ratelimit`, "Open-banking partner rate") is still at
100/60s, confirming 100 is the intended value and that the two providers are
currently enforcing different limits for the same partner traffic.

Applying golden restores `averageThreshold` to 100 for rate policy `9101`, which
re-converges the Akamai edge with Cloudflare and with the approved partner limit.

Before merge: confirm with the partner-API owner that 1000 was not an agreed
temporary uplift.

## Apply side effects

The pipeline applies the whole golden tree for the domain, not just this field.
For `golden/api.rbcdemo.ca/` at this SHA, compared against the current live
config:

- Akamai property rule tree (`golden/api.rbcdemo.ca/rules/rules.json`, pushed via
  `akamai_property.api`): live tree matches golden field-for-field; only PAPI
  envelope metadata (etag, propertyVersion, ids) differs, so the apply creates a
  new property version with no behavioural change.
- Akamai appsec config `90012`: rate policy `9101` `averageThreshold` is the only
  field that differs; all other policies, WAF rules, match targets, network lists
  and reputation profiles are re-asserted unchanged.
- Cloudflare zone settings, the `http_request_firewall_managed` ruleset and the
  `api.rbcdemo.ca` A record managed in `main.tf` are re-asserted at values the
  zone already holds — no change.
- Not reverted by this apply: the Cloudflare CORS drift on this domain (D-08,
  `Access-Control-Allow-Origin` grew `https://partners.rbcdemo.ca`) lives in the
  `http_response_headers_transform` ruleset, which golden does not manage for
  `api.rbcdemo.ca`. It is unaffected here and still needs its own remediation.
- No findings routed to human review cover `api.rbcdemo.ca`, so this apply does
  not disturb any change awaiting a human decision.
