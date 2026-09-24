# Remediation record — online.rbcdemo.ca (D-01, D-07)

Domain: `online.rbcdemo.ca` (authenticated online banking)
Provider drifted: Cloudflare (zone `2b3c4d5e6f708192a3b4c5d6e7f8091a`)
Golden tree: `golden/online.rbcdemo.ca/` (`main.tf`, `rules/rules.json`, `appsec/security-config.json`)
Golden SHA: `e1312f0dda8813ab08acd9afc112ee0f72deba5501c5c52640f81946802e220a`

Both findings are out-of-band provider drift. Golden already declares the
intended end state, so there is no golden edit to make: remediation is the
pipeline re-applying the existing tree on merge. This file is the record the
reviewer signs off on.

## D-01 — `tls.min_version` (cloudflare, critical)

| | |
|---|---|
| Golden value | `TLSV1_2` (canonical `1.2`) — `golden/online.rbcdemo.ca/rules/rules.json` `$.rules.behaviors[?(@.name=='origin')].options.minTlsVersion`; `main.tf` `cloudflare_zone_setting.online_min_tls_version = "1.2"` |
| Drifted live value | `1.0` — Cloudflare settings `$.result[?(@.id=='min_tls_version')].value`, `modified_on` 2026-02-11 |
| Comparator | `semantic_enum_ge` over the `tls_min_version` table — the observed value must canonicalize to ≥ 1.2 |
| Effect of applying golden | The zone TLS floor is reset to 1.2; TLS 1.0/1.1 handshakes and the legacy cipher suites they imply stop being negotiable at the edge |

Akamai's side of this field is already `TLSV1_2` and matches golden, so only the
Cloudflare path carries the exposure. `tls_1_3` is `on` live and is not declared
in golden, so applying golden does not change it.

## D-07 — `tls.ssl_mode` (cloudflare, critical)

| | |
|---|---|
| Golden value | `strict` — mapping field `tls.ssl_mode` `golden.literal`; `main.tf` `cloudflare_zone_setting.online_ssl = "strict"` |
| Drifted live value | `full` — Cloudflare settings `$.result[?(@.id=='ssl')].value`, `modified_on` 2026-01-10 |
| Comparator | `semantic_enum` over the `ssl_mode` table — `full` and `strict` are distinct canonical values |
| Effect of applying golden | Cloudflare validates the origin certificate chain and hostname for `origin-online.rbcdemo.ca` instead of accepting any certificate on an encrypted origin connection |

Akamai is marked `unsupported` for this field, but its equivalent posture is
present and correct in golden (`origin` behavior `verificationMode: CUSTOM`,
`customValidCnValues`, `originCertsToHonor: STANDARD_CERTIFICATE_AUTHORITIES`),
which makes Cloudflare the weaker of the two paths rather than a modelling
artifact.

Sequencing precondition: confirm the origin presents a publicly trusted
certificate for `origin-online.rbcdemo.ca` before the apply. If it does not,
`strict` will fail requests and fixing the origin certificate is the real
remediation and must be sequenced first.

## Apply side effects

The pipeline applies the whole golden tree, not only the two fields above.
Merging this record therefore also causes:

- **Managed WAF ruleset override reset.** Golden's
  `cloudflare_ruleset.online_managed_waf` declares `sensitivity_level = "medium"`
  on the Cloudflare Managed Ruleset execute rule with only the `wordpress` and
  `joomla` category overrides. The live ruleset carries no `sensitivity_level`
  and an additional rule-level override (`5de7edfa648c4d6891c0e334fca04c1f`
  forced to `log`). Applying golden removes that rule-level override — the rule
  returns to its managed default action — and sets sensitivity to medium.
- **Rulesets present live but absent from golden.** Golden declares only the
  managed-WAF ruleset for this zone. The live zone also has `Custom firewall`
  (geo/ASN blocks), `Rate limits` (login limit), `Cache settings`,
  `Request transforms`, `Response header transforms` (HSTS) and `Origin routing`
  rulesets. A whole-tree push that reconciles the zone's ruleset set against
  golden will remove them; these are not covered by the two findings above and
  the reviewer should confirm this is intended before merge.
- **D-06 (`headers.security_static`, routed to human_review) is not closed.**
  Golden defines the static security-header transform on the Akamai side only;
  there is no Cloudflare response-header transform in golden, so applying golden
  does not create one on the zone. The migration gap remains after this apply.
- Zone settings that golden does not declare (for example `ciphers`,
  `security_level`, `tls_1_3`, `http3`) are outside the golden tree and are left
  as they are live.

Side effects inform the review; they do not block this record. Whether to merge
is the reviewer's call.

## Follow-up (not code)

Both settings were changed out of band relative to IaC (`min_tls_version`
2026-02-11, `ssl` 2026-01-10). Identify who made those changes and close the
path that allowed them, otherwise the zone will drift again after this apply.
