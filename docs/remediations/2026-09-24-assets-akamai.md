# Remediation record — assets.rbcdemo.ca (Akamai), 2026-09-24

Golden sha: `e51794e7e57b9fd36eece96c8e9fad80de3254eaab34c60b6ac76c980fd5ca66`
Live property: `prp_540077` v12
Findings: `auth.token_auth_downloads` (high), `caching.default_ttl` (medium)

Both fields drifted at the provider only; `golden/assets.rbcdemo.ca/rules/rules.json`
already holds the intended values, so no golden value changed in this PR. The
corrective action is an apply of the existing golden module
(`akamai_property.assets`, then the staging and production activations), which
rebuilds the rule tree from golden and supersedes v12.

| Field | Golden (intended) | Live v12 | After apply |
| --- | --- | --- | --- |
| `rules.children['Downloads token auth'].behaviors['verifyTokenAuthorization'].options.enabled` | `true` | `false`, comment cites incident EDG-2201 | `true`, golden rule comment restored |
| `rules.behaviors['caching'].options.ttl` | `4h` | `1d` | `4h` |

Precondition before apply: the EDG-2201 incident owner must confirm the
mitigation (token auth off on `/downloads/*` and `/secure/*`) is no longer
needed, because the apply re-enables `__token` validation on those paths.

Cross-check: Cloudflare `browser_cache_ttl` on the assets zone is 14400s (4h),
consistent with keeping golden's `4h` default TTL rather than adopting `1d`.
