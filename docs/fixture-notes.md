# Fixture notes — phase 01

Everything in `fixtures/` is synthetic. No real account IDs, contracts, edge
hostnames, certificates, or customer domains — `rbcdemo.ca` is a placeholder
invented for this demo. IPs are from TEST-NET-2/TEST-NET-3 documentation ranges.

## Targeted versions

- **Akamai PAPI rule format**: `v2023-01-05` (Ion product, `prd_Ion`).
- **Akamai Terraform provider**: `~> 6.2` in golden files.
- **Cloudflare Terraform provider**: `~> 5.0`. Resource names verified against
  the v5 upgrade guide (terraform-provider-cloudflare, `version-5-upgrade.md`):
  `cloudflare_zone_settings_override` is gone in v5 — each setting is a
  separate **`cloudflare_zone_setting`** resource; `cloudflare_record` is now
  **`cloudflare_dns_record`**; **`cloudflare_ruleset`** keeps its name.
- **`terraform init` was not run** (no provider downloads against the network);
  golden files are verified with `terraform fmt -check` only.

## Deliberate choices

- `appsec.json` exists only for `www` and `online`, per the phase spec; the
  API property's rate policies are represented inside the rule tree instead
  (see guesses below).
- `dns_records.json` keeps `CNAME -> *.edgekey.net` (proxied off) for
  `online` and `assets` — those hostnames are still Akamai-primary mid-migration.
- `online`'s `http_response_headers_transform` ruleset lacks the
  `security-headers` rule the golden Terraform declares — the migration gap
  in scenario D-06.
- `assets`'s settings response omits `http2` entirely (suppression case S-02);
  the mapping `defaults:` block supplies the provider default `on`.
- `assets` Akamai `minTlsVersion` is `DYNAMIC`, which resolves to TLS 1.2
  through the value table (suppression case S-01).

## Schema guesses (flagged, not verified against live APIs)

1. **`rateLimit` property-rule behavior** — invented for the login/partner rate
   rules. Real Akamai rate policies live in the App & API Protector export
   (`appsec.json`), not the PAPI rule tree; we use a plausible behavior shape
   (`requestsPerPeriod`, `period`, `action`, `burstAllowance`) so the
   rate-limiting scenarios can live in `rules.json`.
2. **`originFailureRecoveryPolicy`** — plausible stand-in for Akamai origin
   failover options on `online`; exact option names for failover were not
   confirmed from the behavior catalog.
3. **`tokenAuthorization`** — Akamai's token-auth behavior is commonly referred
   to as "Auth Token 2.0"; the emitted behavior name/options were not
   re-verified against rule format v2023-01-05.
4. **`jwtValidation`, `apiShield`, `botManagement`, `imageAndVideoManager`,
   `constructResponse`, `downstreamCache`** — plausible behavior names with
   realistic option shapes; a real export would use the catalog names from the
   product's rule-format schema.
5. **`denyAccess`** — the modern PAPI behavior for blocking may emit as a
   different name/options shape depending on rule format version.
6. **Cloudflare ruleset `action_parameters` shapes** — `execute` overrides,
   `route` origin parameters, `set_cache_settings` `cache_key.custom_key`, and
   transform `headers` blocks are written in the documented v4 style; minor
   key names may differ from a live export (e.g. transform rules may emit
   `uri`/`headers` structures slightly differently).
7. **Zone `settings` list composition** — a real `/settings` response returns
   a larger set with `editable`/`modified_on` metadata varying by entitlement;
   we include ~25 representative settings.
8. **`hostnames.nextLink` / `propertyVersion`-level envelope fields** in
   `hostnames.json` are simplified to what the demo needs.
9. **`zone.json` account/plan/permission fields** are representative, not
   exhaustive.

Where a guess later proves wrong, fix the fixture *and* the mapping path in
the same commit — the validator fails loudly when a path no longer resolves.
