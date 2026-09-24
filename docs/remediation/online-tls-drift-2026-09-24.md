# Remediation record — online.rbcdemo.ca Cloudflare TLS drift (2026-09-24)

Golden SHA compared against:
`e1312f0dda8813ab08acd9afc112ee0f72deba5501c5c52640f81946802e220a`

Both findings are Cloudflare zone-level settings that drifted out of band from the
IaC that manages them. The golden tree (`golden/online.rbcdemo.ca/`) already
declares the correct values, so no configuration change is needed — remediation
is a re-apply of the existing resources, triggered by merging this record.

## D-01 — `tls.min_version` (critical)

| | |
| --- | --- |
| Golden | `TLSV1_2` (floor, canonical 1.2) |
| Observed on Cloudflare | `1.0` |
| Provider path | `settings[?(@.id=='min_tls_version')].value` |
| Declared in IaC | `cloudflare_zone_setting.online_min_tls_version` = `"1.2"` |

The zone completes handshakes with clients offering TLS 1.0/1.1, which carry
known downgrade and CBC-padding weaknesses, on an authenticated banking
hostname. Akamai's origin behavior still reads `TLSV1_2`, so this is a real
disagreement between the two edges on the client-side floor, not a vocabulary
difference.

Action: re-apply `cloudflare_zone_setting.online_min_tls_version`. After the
apply, the zone rejects TLS 1.0/1.1 client handshakes.

## D-07 — `tls.ssl_mode` (critical)

| | |
| --- | --- |
| Golden | `strict` |
| Observed on Cloudflare | `full` |
| Provider path | `settings[?(@.id=='ssl')].value` |
| Declared in IaC | `cloudflare_zone_setting.online_ssl` = `"strict"` |

`full` encrypts the Cloudflare-to-origin hop but accepts any certificate the
origin presents — self-signed, expired, or wrong-hostname — so that leg is
encrypted but not authenticated and remains open to on-path impersonation of the
origin. `strict` validates the origin certificate against a trusted CA. The
Akamai side is unsupported for this field and was skipped; for reference its
origin behavior uses `verificationMode` `CUSTOM` against the akamai-perimeter
CAs.

Action: re-apply `cloudflare_zone_setting.online_ssl`. After the apply,
Cloudflare validates the origin certificate on every origin connection.

Precondition: confirm `origin-online.rbcdemo.ca` presents a publicly trusted
certificate for that hostname before applying. `cloudflare_dns_record.online_root`
is currently `proxied = false` (Akamai-primary, CF cutover pending), so `strict`
has no request-path effect today, but it will start failing requests the moment
the record is proxied if the origin certificate is not trusted.

## Needs manual action

- Neither finding is closable with a configuration edit: the golden Terraform is
  already correct, so the remediation is an apply, not a diff. The pipeline
  should re-apply the two resources above for zone
  `2b3c4d5e6f708192a3b4c5d6e7f8091a`.
- Identify who changed `ssl` and `min_tls_version` on the zone outside
  Terraform (Cloudflare audit logs; the settings report `modified_on`
  2026-01-10 and 2026-02-11 respectively) and close off that access path, or the
  drift recurs after the apply.
