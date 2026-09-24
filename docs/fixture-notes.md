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

- `appsec.json` exists for `www`, `online`, and `api`. Rate policies and bot
  management live there (as they do on a real Akamai footprint) — the property
  rule tree has no rate-limit or bot-management behaviors. The golden
  counterpart is `golden/<domain>/appsec/security-config.json`, referenced
  from `main.tf` via `local.appsec_config` so intended values live in one
  place. `assets` has no App Sec config (CDN-only product scope).
- `dns_records.json` keeps `CNAME -> *.edgekey.net` (proxied off) for
  `online` and `assets` — those hostnames are still Akamai-primary mid-migration.
- `online`'s `http_response_headers_transform` ruleset lacks the
  `security-headers` rule the golden Terraform declares — the migration gap
  in scenario D-06.
- `assets`'s settings response omits `http2` entirely (suppression case S-02);
  the mapping `defaults:` block supplies the provider default `on`.
- `assets` Akamai `minTlsVersion` is `DYNAMIC`, which resolves to TLS 1.2
  through the value table (suppression case S-01).

## Schema verification status

All behavior and criteria names in the rule trees were checked against
Akamai's Property Manager behavior/criteria reference (techdocs.akamai.com,
`latest-behaviors` / `latest-criteria` index). Names verified in the catalog:
`origin`, `cpCode`, `caching`, `cacheKeyQueryParams`, `sureRoute`,
`tieredDistribution`, `prefetch`, `allowPost`, `http2`, `http3`,
`gzipResponse`, `report`, `mPulse`, `webApplicationFirewall`,
`adaptiveAcceleration`, `enhancedAkamaiProtocol`, `removeVary`,
`modifyOutgoingResponseHeader`, `modifyIncomingRequestHeader`, `datastream`,
`setVariable`, `redirect`, `denyAccess`, `downstreamCache`,
`constructResponse`, `simulateErrorCode`, `imageManager`,
`verifyTokenAuthorization`, `originFailureRecoveryPolicy`,
`centralAuthorization`. Criteria names `path`, `fileExtension`,
`requestHeader`, `requestMethod`, `hostname`, `userLocation`, `cookie`,
`queryStringParameter`, `matchVariable` are likewise catalog names.

Corrections made after verification: token auth uses
`verifyTokenAuthorization` (not `tokenAuthorization`); Image Manager is
`imageManager` (not `imageAndVideoManager`); rate limiting, bot management,
and API schema enforcement are App Sec / Bot Manager concerns and moved into
`appsec.json`; the fabricated `jwtValidation`/`apiShield`/`rateLimit`
behaviors were removed (the JWT intent is carried by `centralAuthorization`).

### Remaining guesses (options/shape level)

1. **Option keys inside verified behaviors** — e.g. `verifyTokenAuthorization`
   (`location`, `locationName`, `escapeEarly`), `originFailureRecoveryPolicy`
   (`failureRetryTime`, `maxRetries`, `retryMethods`), `constructResponse`
   (`contentType`), `centralAuthorization` (`authServerHostname`),
   `downstreamCache` value `BUST`, `imageManager` `applyBestFileType`. The
   behavior names are catalog-verified; individual option spellings were
   written in documented style but not all re-verified key-by-key for
   rule format `v2023-01-05`.
2. **Cloudflare `action_parameters` shapes** — `execute` overrides,
   `route` origin parameters, `set_cache_settings` `cache_key.custom_key`,
   and transform `headers` blocks follow the documented v4 API shape; minor
   key names may differ from a live export.
3. **Envelope completeness** — `zone.json`, `hostnames.json`, the settings
   list (~25 of a real response's larger set), and `appsec.json` carry
   representative fields, not every field a live export emits.
4. **`apiConstraints` / `botManagement` blocks in `appsec.json`** — plausible
   App Sec export subsections; a real App & API Protector export splits these
   across several endpoints.

Where a guess later proves wrong, fix the fixture *and* the mapping path in
the same commit — the validator fails loudly when a path no longer resolves.
