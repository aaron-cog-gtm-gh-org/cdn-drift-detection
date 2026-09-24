# Seeded drift scenarios — phase 01

Twelve scenarios are seeded into the fixtures. Ten must produce findings; two
are suppression cases that must produce *none* (they prove the mapping is
semantic, not textual). `route` is the remediation route the orchestrator will
choose in phase 02: `iac_pr` (fix Terraform), `provider_api` (fix at the
provider), `human` (needs a person to decide).

The validator (`scripts/validate_fixtures.py`) asserts its output equals the
`expected_findings` block at the bottom of this file exactly — field id,
provider, severity, domain.

| # | id | Domain | Provider | Mapped field | Golden | Fixture | Severity | Route | Why it matters |
|---|----|--------|----------|--------------|--------|---------|----------|-------|----------------|
| 1 | D-01 | online | cloudflare | `tls.min_version` | `1.2` | `1.0` | critical | iac_pr | PCI-DSS 4.0 requires TLS 1.2+ on any channel carrying account data; TLS 1.0 on authenticated banking is audit-critical. |
| 2 | D-02 | www | cloudflare | `waf.managed_ruleset_enabled` | `enabled` | `enabled: false` on the managed-ruleset execute rule | critical | iac_pr | The Cloudflare Managed Ruleset execute rule was disabled — the whole managed WAF layer silently no-ops on the marketing surface. |
| 3 | D-03 | api | akamai | `ratelimit.partner_api` | `100` req/min | `1000` req/min | high | iac_pr | Open-banking partner rate was raised 10× out-of-band (rule comment cites EDG-2309); throttling boundary no longer matches the approved limit. |
| 4 | D-04 | assets | akamai | `caching.default_ttl` | `4h` | `1d` | medium | iac_pr | Default TTL tripled past policy; stale assets can outlive a content takedown window. |
| 5 | D-05 | www | akamai | `origins.hostname_set` | `{origin-www}` | `{origin-www, origin-campaign}` | high | human | Extra origin hostname appeared in the live tree with no Terraform record — someone must decide whether the edge is right or the golden is stale. |
| 6 | D-06 | online | cloudflare | `headers.security_static` | present | absent from `http_response_headers_transform` | medium | human | Golden defines a static security-header transform for online banking; Cloudflare has no counterpart yet — a migration gap, not drift. |
| 7 | D-07 | online | cloudflare | `tls.ssl_mode` | `strict` | `full` | critical | iac_pr | `full` accepts an invalid origin certificate; `strict` validates it. On authenticated banking this breaks the end-to-end TLS story. |
| 8 | D-08 | api | cloudflare | `cors.allowed_origins` | `{online, www}` | `{online, www, partners}` | high | iac_pr | CORS allowlist grew a third origin the golden never approved — credential-bearing cross-origin access to the API surface. |
| 9 | D-09 | www | akamai | `tls.hsts_max_age` | `31536000` | `86400` | medium | iac_pr | HSTS max-age dropped from a year to a day; the preload posture is effectively lost between visits. |
| 10 | D-10 | assets | akamai | `auth.token_auth_downloads` | `enabled` | `enabled: false` | high | iac_pr | Token auth on `/downloads/*` was switched off during incident EDG-2201 and never re-enabled — protected assets are fetchable without signatures. |
| 11 | S-01 | assets | both | `tls.min_version` | Akamai `DYNAMIC` | CF `1.2` | — | — | Suppression: `DYNAMIC` resolves to TLS 1.2 via the value table; semantically equal, no finding. |
| 12 | S-02 | assets | cloudflare | `http.http2` | `on` | setting omitted from the zone-settings response | — | — | Suppression: the omitted setting sits at its provider default `on`; the defaults block suppresses the false positive. |

```expected_findings
- {id: D-01, domain: online.rbcdemo.ca, provider: cloudflare, field: tls.min_version, severity: critical, route: iac_pr}
- {id: D-02, domain: www.rbcdemo.ca, provider: cloudflare, field: waf.managed_ruleset_enabled, severity: critical, route: iac_pr}
- {id: D-03, domain: api.rbcdemo.ca, provider: akamai, field: ratelimit.partner_api, severity: high, route: iac_pr}
- {id: D-04, domain: assets.rbcdemo.ca, provider: akamai, field: caching.default_ttl, severity: medium, route: iac_pr}
- {id: D-05, domain: www.rbcdemo.ca, provider: akamai, field: origins.hostname_set, severity: high, route: human}
- {id: D-06, domain: online.rbcdemo.ca, provider: cloudflare, field: headers.security_static, severity: medium, route: human}
- {id: D-07, domain: online.rbcdemo.ca, provider: cloudflare, field: tls.ssl_mode, severity: critical, route: iac_pr}
- {id: D-08, domain: api.rbcdemo.ca, provider: cloudflare, field: cors.allowed_origins, severity: high, route: iac_pr}
- {id: D-09, domain: www.rbcdemo.ca, provider: akamai, field: tls.hsts_max_age, severity: medium, route: iac_pr}
- {id: D-10, domain: assets.rbcdemo.ca, provider: akamai, field: auth.token_auth_downloads, severity: high, route: iac_pr}
```
