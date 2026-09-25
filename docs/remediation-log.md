# Remediation log

One entry per cross-provider drift finding remediated through this repo.
Under the current model there is no golden state: a detection session finds
the two providers disagreeing, a human decides which side is right, and the
session opens a PR fixing the *losing* provider's Terraform
(`terraform/<domain>/<provider>/…`). Each entry records what a reviewer
needs in order to approve the merge: the two live values seen, the human's
decision, the file and value the PR changes, and the PR link.

## ratelimit.partner_api — api.rbcdemo.ca — akamai — high

- Providers disagreed: Akamai App Sec policy 9101 ("Open-banking partner
  rate") at `averageThreshold` **1000** req/60s; Cloudflare partner rate
  limit at **100** req/60s (path `/open-banking/*`, action `deny`, on both
  sides).
- Decision (operator): Cloudflare is right — 100 req/60s is the approved
  partner grant; the 1000 is an out-of-band Akamai edit and is not ratified.
- Remediation: `averageThreshold` stays `100` in the checked-in
  `terraform/api.rbcdemo.ca/akamai/appsec.json` (the JSON the
  `akamai_appsec_rate_policy.api_partner` resource renders from); the live
  Akamai-side edit was corrected by apply. No Cloudflare change.
- Detected against `iac_sha`
  `163cd6281894b30af5623b11174b9b2ee5b968e387654bcd455b89d5b0a0f967`.

*(Earlier entries from the retired golden-state model were removed when the
golden store was deleted; see git history for them.)*
