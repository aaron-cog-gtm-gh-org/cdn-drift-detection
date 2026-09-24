# Remediation record — assets.rbcdemo.ca (D-04, D-10)

Golden tree: `golden/assets.rbcdemo.ca/` at golden_sha
`e51794e7e57b9fd36eece96c8e9fad80de3254eaab34c60b6ac76c980fd5ca66`.
Live property compared: Akamai `prp_540077` v12 (`assets.rbcdemo.ca`).

Both findings are provider drift away from a golden tree that is already
correct, so there is no golden edit to make. Remediation is the pipeline
re-applying `golden/assets.rbcdemo.ca/` on merge; this document is the record
the reviewer signs off on.

## D-10 — `auth.token_auth_downloads` (akamai, high)

- Golden path: `golden/assets.rbcdemo.ca/rules/rules.json`
  `$.rules.children[?(@.name=='Downloads token auth')].behaviors[?(@.name=='verifyTokenAuthorization')].options.enabled`
- Golden value: `true`
- Live value: `false` (rule comment: "DISABLED during EDG-2201 incident
  response - re-enable pending; golden still ON.")
- Effect of applying golden: the `verifyTokenAuthorization` behavior is
  re-enabled, so the edge again validates the `__token` query-string parameter
  on `/downloads/*` and `/secure/*`. The rule itself and its path criteria are
  unchanged — only the behavior toggle (and the incident comment) differ.
- Cloudflare is marked unsupported for this field (signed URLs would live in
  Workers/Access), so Akamai is the only place this control exists today.

Pre-merge condition: confirm with the EDG-2201 owners that the
incident-response exception has expired.

## D-04 — `caching.default_ttl` (akamai, medium)

- Golden path: `golden/assets.rbcdemo.ca/rules/rules.json`
  `$.rules.behaviors[?(@.name=='caching')].options.ttl`
- Golden value: `4h` (14400s)
- Live value: `1d` (86400s)
- Effect of applying golden: the default rule's `MAX_AGE` caching behavior
  returns to 14400s. The per-rule overrides are unchanged (Long-TTL media 30d,
  Versioned assets 365d, query-param cache-key rule), so this affects only
  traffic not matched by those rules.
- Cloudflare's `browser_cache_ttl` for the same mapped field is already 14400
  and matches golden; applying golden also removes the current cross-provider
  disagreement.

## Apply side effects

The pipeline pushes the whole golden tree, not just the two fields above.
Applying `golden/assets.rbcdemo.ca/` will additionally:

1. **Akamai — rule comment reverts.** The "Downloads token auth" rule comment
   goes from the EDG-2201 incident note back to "Token auth required on
   /downloads/* and /secure/*." Cosmetic; it removes the only in-config record
   of the incident exception.
2. **Cloudflare — managed WAF ruleset is rewritten to golden.** The live
   `Cloudflare Managed + OWASP` ruleset carries an out-of-band per-rule
   override (`5de7edfa648c4d6891c0e334fca04c1f` → action `log`, enabled) that
   golden does not contain, and omits golden's
   `overrides.sensitivity_level = "medium"` on the managed-ruleset execute
   rule. Applying golden drops that rule-level override and restores
   sensitivity `medium`. This was not one of the routed findings.
3. **Cloudflare — `http2` is set explicitly.** The live zone-settings response
   omits `http2` (suppression case S-02: omitted means the provider default
   `on`). Golden declares `http2 = "on"`, so the apply writes the setting
   explicitly. No behavioural change.

Not affected: the live `Custom firewall`
(`http_request_firewall_custom`) ruleset is not declared in
`golden/assets.rbcdemo.ca/main.tf`, so the apply leaves it in place. Akamai
`tls.min_version` remains `DYNAMIC` (suppression case S-01, semantically equal
to Cloudflare's `1.2`).
