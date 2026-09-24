# Remediation record — www.rbcdemo.ca (D-02, D-09)

Golden SHA compared: `5f2e2050bf28c3734ef72160eb794f41f90cd032f31e2a2a7083eeebaf034cb9`
Golden tree: `golden/www.rbcdemo.ca/` (`main.tf`, `rules/rules.json`, `appsec/security-config.json`)

Both findings are provider-side drift away from the golden tree. Golden already
declares the intended end state for each field, so there is no golden edit in
this change: remediation is the pipeline re-applying the existing tree on merge.
This document is the record the reviewer signs off on.

## D-02 — `waf.managed_ruleset_enabled` (Cloudflare, critical)

- Golden: `true` — `cloudflare_ruleset.www_managed_waf` `rules[0].enabled = true`
  (mapping field `waf.managed_ruleset_enabled`, `golden.literal = true`).
- Live: `false` — `rulesets[phase='http_request_firewall_managed' id=def0123456789abcdef0123456789abc].rules[description='Execute Cloudflare Managed Ruleset' id=3456789abcdef0123456789abcdef012].enabled`.
- Effect of the drift: the execute rule that invokes the Cloudflare Managed
  Ruleset is still present but disabled, so the managed rule engine never runs
  on this zone. Only the second execute rule (OWASP Core Ruleset, sensitivity
  medium) is live. The zone-level `waf` setting being `on` does not compensate —
  it permits the WAF engine, it does not execute a ruleset. The overrides on the
  disabled rule (wordpress/joomla categories set to log, one rule id forced to
  log) have no effect while the rule is off.
- Applying golden restores it: the declared `enabled = true` re-enables the
  Managed Ruleset execute rule.
- Also reconciled by the same apply (live rule vs Terraform): golden declares
  `overrides.sensitivity_level = "medium"` on this rule and no per-rule
  override; the live rule has no `sensitivity_level` and an override forcing
  rule `5de7edfa648c4d6891c0e334fca04c1f` to `log`.
- Follow-up outside this change: the live ruleset diverged from the last apply,
  so the drift source is still unexplained. A console toggle would have fixed
  the symptom only; confirm how the zone diverged.

## D-09 — `tls.hsts_max_age` (Akamai, medium)

- Golden: `max-age=31536000; includeSubDomains; preload` (31536000s) at
  `rules/rules.json` `$.rules.behaviors[?(@.options.customHeaderName=='Strict-Transport-Security')].options.customHeaderValue`.
- Live: `max-age=86400` (86400s) at
  `rules.rules.behaviors[name='modifyOutgoingResponseHeader', options.customHeaderName='Strict-Transport-Security'].options.customHeaderValue`.
- Effect of the drift: the comparator is `numeric_ge` on the `max-age` capture,
  so golden's 31536000 is a floor and Akamai's one day is below it. The
  directive has also lost `includeSubDomains` and `preload`, so the pin no
  longer covers subdomains at all. This is the only
  `Strict-Transport-Security` header in the property tree and HSTS is not
  expressed in the App Sec config, so the control has not moved elsewhere in
  the Akamai model.
- Applying golden restores it: the pipeline activates a new property version
  emitting `max-age=31536000; includeSubDomains; preload`.
- Cross-provider note: Cloudflare's copy of the same header still meets the
  floor (`max-age=31536000; includeSubDomains`), so until the Akamai property
  is reactivated the two edges pin this hostname for materially different
  periods depending on which one served the response. Cloudflare's header
  transform is not declared in `golden/www.rbcdemo.ca/main.tf` at all, so
  making both edges emit an identical string (adding `preload` on the
  Cloudflare side) is a golden-intent change and is deliberately not part of
  this record — see the PR description.

## Apply side effects

The pipeline applies whole-tree: it pushes the entire golden Akamai rule tree
and the declared Cloudflare zone configuration, not only the fields above.
Merging therefore also reverts these out-of-band provider changes on
www.rbcdemo.ca:

- **D-05 `origins.hostname_set` (Akamai, high, routed to human review)** — the
  live rule tree carries an extra child rule `Campaign microsite origin` with
  an `origin` behavior for `origin-campaign.rbcdemo.ca` that golden does not
  declare. Applying golden removes that rule and the second origin, so any
  traffic depending on the campaign microsite origin stops being routed there.
- **Cloudflare managed-WAF override differences (D-02 above)** — the per-rule
  `log` override on `5de7edfa648c4d6891c0e334fca04c1f` is dropped and
  `sensitivity_level = "medium"` is restored on the Managed Ruleset execute
  rule, so any rule currently only logging starts acting per the managed
  ruleset defaults.

No other diffs exist between the live www.rbcdemo.ca Akamai tree and golden,
and the live Cloudflare zone settings (`ssl`, `min_tls_version`,
`always_use_https`, `http2`, `brotli`) and DNS record already match golden.

These side effects inform the review; whether to merge is the reviewer's call.
