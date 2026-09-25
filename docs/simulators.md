# Provider simulators — phase 02

Two read-only FastAPI services that serve the phase-01 fixtures verbatim over
provider-shaped HTTP APIs. They exist so the drift-checking orchestrator can
pull config the same way it would in a real RBC deployment.

## Running

```sh
~/cdn-drift-venv/bin/python -m sim.run --provider akamai     --port 8081
~/cdn-drift-venv/bin/python -m sim.run --provider cloudflare --port 8082
# or both:
scripts/run_simulators.sh
```

`GET /healthz` on either returns `{"status":"ok","provider":...,"domains":[...]}`
— a simulator convenience, **not** part of the real APIs.

## Akamai (PAPI v1 + App Sec v1), port 8081

| Endpoint | Serves |
| --- | --- |
| `GET /papi/v1/properties?contractId=&groupId=` | `properties.json`; filters items by the pair (one without the other → 400) |
| `GET /papi/v1/properties/{propertyId}` | same envelope, one item; unknown → 404 |
| `GET /papi/v1/properties/{propertyId}/versions/{v}/rules` | `<domain>/rules.json` verbatim; wrong version → 404 |
| `GET /papi/v1/properties/{propertyId}/versions/{v}/hostnames` | `<domain>/hostnames.json` verbatim |
| `GET /appsec/v1/configs` | `{"configurations": [...]}` — one entry per appsec fixture with `id`, `name`, `description`, `latestVersion`, `stagingVersion`, `productionVersion`, `productionHostnames` |
| `GET /appsec/v1/export/configs/{configId}/versions/{versionNumber}` | `appsec.json` matching `configId`+`configVersion` |

- **Auth:** requires `Authorization: EG1-HMAC-SHA256 client_token=...;access_token=...;timestamp=...;nonce=...;signature=...`. Missing/malformed → 401. The signature is **not verified**.
- **`PAPI-Use-Prefixes: false`** strips `prp_ ctr_ grp_ act_ aid_ ehn_ cpc_` from every string value, recursively.
- **`ETag`/`If-None-Match`:** fixture `etag` is sent on rules and hostnames responses; matching `If-None-Match` → 304.
- Errors use RFC 7807 `application/problem+json` (`type`, `title`, `detail`, `status`, `instance`).

```sh
curl -s -H "Authorization: EG1-HMAC-SHA256 client_token=sim;access_token=sim;timestamp=2026-01-01T00:00:00Z;nonce=n;signature=sig" \
  http://127.0.0.1:8081/papi/v1/properties/prp_512345/versions/47/rules | jq .ruleFormat
```

## Cloudflare (client/v4), port 8082

| Endpoint | Serves |
| --- | --- |
| `GET /zones?name=<fqdn>` | list envelope of matching zone objects + `result_info` |
| `GET /zones/{zone_id}` | `zone.json` result verbatim |
| `GET /zones/{zone_id}/settings` | `settings.json` verbatim |
| `GET /zones/{zone_id}/settings/{setting_id}` | one setting; absent → 404 envelope |
| `GET /zones/{zone_id}/rulesets` | rulesets **without** `rules` (list omits rules like the real API) |
| `GET /zones/{zone_id}/rulesets/{ruleset_id}` | one ruleset **with** `rules` |
| `GET /zones/{zone_id}/rulesets/phases/{phase}/entrypoint` | ruleset for that phase, with rules |
| `GET /zones/{zone_id}/dns_records?page=&per_page=` | paginated `dns_records.json` |

- **Auth:** `Authorization: Bearer $CLOUDFLARE_SIM_TOKEN` (default `demo-token`). Missing/malformed → 400 code `6003`; wrong token → 403 code `9109`.
- Errors: `{"success":false,"errors":[{"code","message"}],"messages":[],"result":null}`.

```sh
curl -s -H "Authorization: Bearer demo-token" \
  "http://127.0.0.1:8082/client/v4/zones?name=www.rbcdemo.ca" | jq .result[0].id
```

## Where the simulation is approximate

- **EdgeGrid signature is not verified** — only the header shape is checked.
- **Cloudflare error codes are approximations** — `6003` (invalid headers) and
  `9109` (invalid token) mimic real CF codes but were chosen, not observed.
- **Subdomain zones** — each fixture domain is its own Cloudflare zone
  (`name: www.rbcdemo.ca` etc.), modelling Enterprise subdomain-zone support;
  a real estate might instead be one `rbcdemo.ca` zone with per-host config.
- **`/healthz` is invented** for both providers.
- **`GET /appsec/v1/configs` field set is verified** — it emits exactly the
  TechDocs schema for `List security configurations`
  (application-security/reference/get-configs): `id` (integer), `name`,
  `description`, `latestVersion`, `stagingVersion`, `productionVersion`,
  `productionHostnames`. Nothing outside that set.
- `PAPI-Use-Prefixes: false` strips every matching string value, including
  places where the real API might keep prefixes (e.g. inside comments).
- `result_info.total_pages`/`count` follow Cloudflare's documented envelope;
  cursors, `result_info.cursors`, and rate-limit headers are omitted.
- Read-only: no POST/PUT/PATCH, no activation/purge flows, no rate limiting.
