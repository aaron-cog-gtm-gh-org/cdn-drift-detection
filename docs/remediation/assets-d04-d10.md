# Remediation record — assets.rbcdemo.ca (D-04, D-10)

Golden sha compared: `e51794e7e57b9fd36eece96c8e9fad80de3254eaab34c60b6ac76c980fd5ca66`
Drifted provider object: Akamai property `prp_540077` (`assets.rbcdemo.ca`), version 12.

Both findings are Akamai-side drift against a golden tree that is already correct,
so remediation is an apply of the existing golden rule tree
(`golden/assets.rbcdemo.ca/rules/rules.json`, pushed by
`data.akamai_property_rules_template.assets` -> `akamai_property.assets`), not an
edit to golden. No Cloudflare change is involved: the zone is DNS-only for this
hostname (`cloudflare_dns_record.assets_root`, `proxied = false`) and
`browser_cache_ttl` already matches golden at 14400.

## D-10 `auth.token_auth_downloads` (high, owner edge-security, OSFI B-13 asset integrity)

- Golden: `$.rules.children[?(@.name=='Downloads token auth')].behaviors[?(@.name=='verifyTokenAuthorization')].options.enabled` = `true`
- Live on version 12: `false`, rule comment
  "DISABLED during EDG-2201 incident response — re-enable pending; golden still ON."
- Applying golden restores `enabled = true` and resets the rule comment to the
  golden text. The rest of the token configuration (`/downloads/*`, `/secure/*`
  path criteria, `QUERY_STRING` / `__token` / `TRANSIENT`) is unchanged on both
  sides, so the apply flips only the enforcement switch.
- No compensating control exists: the property carries no App Sec configuration
  and the Cloudflare zone has no Workers/Access signed-URL equivalent.

Manual gate before apply: the EDG-2201 owner must confirm incident response no
longer needs token auth off.

## D-04 `caching.default_ttl` (medium, owner edge-platform)

- Golden: `$.rules.behaviors[?(@.name=='caching')].options.ttl` = `4h`
- Live on version 12: `1d`
- Applying golden restores the default-rule edge max-age to 4h.
  `behavior = MAX_AGE` and `mustRevalidate = false` are unchanged; more specific
  rules (Long-TTL media 30d, Versioned assets 365d) are unaffected.
