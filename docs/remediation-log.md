# Remediation log

One entry per confirmed drift finding remediated through this repo. Records the
decision a reviewer needs in order to approve the apply.

## ratelimit.partner_api — api.rbcdemo.ca — akamai — high

- Detected against golden_sha `163cd6281894b30af5623b11174b9b2ee5b968e387654bcd455b89d5b0a0f967`.
- Golden (`golden/api.rbcdemo.ca/appsec/security-config.json`, `rp_partner`):
  `averageThreshold` 100 req / 60s, PATH `/open-banking/*`, action `deny`.
- Live Akamai App Sec (policy id 9101, name "Open-banking partner rate"):
  `averageThreshold` 1000 req / 60s, same period, match and action.
- Decision: golden stands at 100. The 1000 is an out-of-band edit and is not
  ratified as a capacity grant.
- Remediation: apply `akamai_appsec_rate_policy.api_partner`, which renders the
  policy from the checked-in JSON; no golden value change was required.
