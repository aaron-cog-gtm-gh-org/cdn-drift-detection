# Remediation log

One entry per confirmed drift finding remediated through this repo. Records the
decision a reviewer needs in order to approve the apply.

## ratelimit.partner_api — api.rbcdemo.ca — akamai — high

- Detected against golden_sha
  `0a6300de7c7ebd6ee23e7f5cdf6f5f2e9dc735a02167ec576cd5c550a46bb352`.
- Golden (`golden/api.rbcdemo.ca/appsec/security-config.json`, `rp_partner`):
  `averageThreshold` 100 req / 60s, `burstThreshold` 50, PATH
  `/open-banking/*`, action `deny`.
- Live Akamai App Sec (config 90012 v9, rate policy id 9101, name
  "Open-banking partner rate"): `averageThreshold` 1000 req / 60s — same
  period, matchType, pathMatch, action and `burstThreshold` 50.
- The equivalent Cloudflare rule ("Open-banking partner rate",
  `http_ratelimit`) is still at `requests_per_period` 100, so the Akamai value
  is one-sided and not an estate-wide re-baselining.
- Decision: golden stands at 100. The 1000 is an out-of-band edit and is not
  ratified as a capacity grant. `burstThreshold` 50 already matches golden and
  is intentionally left as-is.
- Remediation: apply `akamai_appsec_rate_policy.api_partner`, which renders the
  policy from the checked-in JSON; no golden value change was required.
