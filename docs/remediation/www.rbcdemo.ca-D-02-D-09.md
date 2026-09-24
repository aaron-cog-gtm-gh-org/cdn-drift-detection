# Remediation record — www.rbcdemo.ca (D-02, D-09)

Golden SHA compared: `5f2e2050bf28c3734ef72160eb794f41f90cd032f31e2a2a7083eeebaf034cb9`
Golden tree: `golden/www.rbcdemo.ca/` (`main.tf`, `rules/rules.json`, `appsec/security-config.json`)

Both findings are provider-side drift away from golden. The golden tree already
declares the intended end state for both fields, so this PR contains no change
to `golden/`: remediation is the pipeline re-applying the existing tree on
merge. This record is what the reviewer signs off on.

## D-02 — `waf.managed_ruleset_enabled` (cloudflare, critical)

- Golden: `true` — `cloudflare_ruleset.www_managed_waf`, rule
  `Execute Cloudflare Managed Ruleset`, `enabled = true`
  (`golden/www.rbcdemo.ca/main.tf`).
- Live: `enabled = false` on
  `rulesets[phase=http_request_firewall_managed, id=def0123456789abcdef0123456789abc].rules[id=3456789abcdef0123456789abcdef012]`.
  The execute rule exists but never invokes the Cloudflare Managed Ruleset
  (`efb7b8c949ac4650a09736fc376e9aee`); the only executing rule left in that
  phase is the OWASP Core Ruleset. The zone-level `waf = on` setting does not
  compensate — it permits the phase to run, it does not execute the ruleset.
- Risk carried: no managed WAF coverage on the marketing and sign-in landing
  surface while the `www` DNS record is proxied through Cloudflare. The Akamai
  side of this field is in sync (`webApplicationFirewall.enable = true`), so
  managed WAF survives only on traffic still served by the Akamai property.
- Applying golden restores it: the managed ruleset executes again on all
  traffic in the `http_request_firewall_managed` phase.

## D-09 — `tls.hsts_max_age` (akamai, medium)

- Golden: `max-age=31536000; includeSubDomains; preload` —
  `golden/www.rbcdemo.ca/rules/rules.json`,
  `$.rules.behaviors[?(@.options.customHeaderName=='Strict-Transport-Security')].options.customHeaderValue`.
- Live: `max-age=86400`, with `includeSubDomains` and `preload` lost, on the
  default-rule `modifyOutgoingResponseHeader` behavior.
- Risk carried: HSTS pinning falls from a year to a day and stops covering
  subdomains, so the preload posture is effectively lost between visits and
  a downgrade/stripping window reopens on Akamai-served traffic. The
  Cloudflare response-header transform for the same header still sends
  `max-age=31536000`, so only the Akamai property is affected.
- Applying golden restores it: the property re-activates with
  `max-age=31536000; includeSubDomains; preload`.

## Apply side effects

The pipeline applies whole-tree, so merging also reverts these out-of-band
provider changes that are not part of the findings routed here. They are listed
for review, not as blockers.

1. **Akamai — `Campaign microsite origin` child rule is removed** (finding
   D-05, `origins.hostname_set`, routed to human review). The live www rule
   tree carries a child rule commented
   `ADDED out-of-band 2026-08-14 — not yet in TF golden (ticket EDG-2211)`
   that routes `promo.rbcdemo.ca` to `origin-campaign.rbcdemo.ca`. Golden has
   no such rule, so re-activating the golden tree deletes it and the campaign
   microsite loses its origin. If that origin is legitimate, it must be added
   to golden before this is applied — that decision belongs to the D-05
   reviewer, not to this PR.
2. **Cloudflare — individual managed-rule override is dropped.** The live
   execute rule carries an override setting managed rule
   `5de7edfa648c4d6891c0e334fca04c1f` to `log`, which is not in the Terraform.
   Applying golden removes it, so that rule returns to its managed-ruleset
   default action. This is intentional: it is a dashboard-added weakening of
   the same ruleset D-02 is restoring, and codifying it would keep part of the
   managed layer in log-only mode. The `wordpress` and `joomla` category
   overrides (both `log`) are already declared in golden and survive the
   apply unchanged.
