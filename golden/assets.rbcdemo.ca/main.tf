terraform {
  required_providers {
    akamai = {
      source  = "akamai/akamai"
      version = "~> 6.2"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
  }
}

locals {
  domain         = "assets.rbcdemo.ca"
  akamai_edge    = "assets-rbcdemo-ca.edgekey.net"
  origin_host    = "origin-assets.rbcdemo.ca"
  cf_zone_id     = "4d5e6f708192a3b4c5d6e7f8091a2b3c"
  drift_baseline = true
}

# ---------- Akamai ----------

resource "akamai_cp_code" "assets" {
  name        = "assets.rbcdemo.ca-cpcode"
  contract_id = "ctr_C-0N7RAC7"
  group_id    = "grp_98765"
  product_id  = "prd_Ion"
}

resource "akamai_edge_hostname" "assets" {
  product_id    = "prd_Ion"
  contract_id   = "ctr_C-0N7RAC7"
  group_id      = "grp_98765"
  edge_hostname = "assets-rbcdemo-ca.edgekey.net"
  ip_behavior   = "IPV4"
  certificate   = akamai_cp_code.assets.id
}

data "akamai_property_rules_template" "assets" {
  template_file = "${path.module}/rules/rules.json"
}

resource "akamai_property" "assets" {
  name        = "assets.rbcdemo.ca"
  contract_id = "ctr_C-0N7RAC7"
  group_id    = "grp_98765"
  product_id  = "prd_Ion"
  rule_format = "v2023-01-05"
  hostnames {
    cname_from             = "assets.rbcdemo.ca"
    cname_to               = akamai_edge_hostname.assets.edge_hostname
    cert_provisioning_type = "CPS_MANAGED"
  }
  rules = data.akamai_property_rules_template.assets.json
}

resource "akamai_property_activation" "assets_staging" {
  property_id                    = akamai_property.assets.id
  network                        = "STAGING"
  version                        = akamai_property.assets.latest_version
  auto_acknowledge_rule_warnings = true
  compliance_record {
    noncompliance_reason_none {}
  }
}

resource "akamai_property_activation" "assets_production" {
  property_id                    = akamai_property.assets.id
  network                        = "PRODUCTION"
  version                        = akamai_property.assets.latest_version
  auto_acknowledge_rule_warnings = true
  compliance_record {
    noncompliance_reason_none {}
  }
}

# ---------- Cloudflare ----------

resource "cloudflare_zone_setting" "assets_ssl" {
  zone_id    = local.cf_zone_id
  setting_id = "ssl"
  value      = "strict"
}

resource "cloudflare_zone_setting" "assets_min_tls_version" {
  zone_id    = local.cf_zone_id
  setting_id = "min_tls_version"
  value      = "1.2"
}

resource "cloudflare_zone_setting" "assets_always_use_https" {
  zone_id    = local.cf_zone_id
  setting_id = "always_use_https"
  value      = "on"
}

resource "cloudflare_zone_setting" "assets_http2" {
  zone_id    = local.cf_zone_id
  setting_id = "http2"
  value      = "on"
}

resource "cloudflare_zone_setting" "assets_brotli" {
  zone_id    = local.cf_zone_id
  setting_id = "brotli"
  value      = "on"
}

resource "cloudflare_ruleset" "assets_managed_waf" {
  zone_id = local.cf_zone_id
  name    = "Cloudflare Managed + OWASP"
  kind    = "zone"
  phase   = "http_request_firewall_managed"

  rules = [
    {
      description = "Execute Cloudflare Managed Ruleset"
      action      = "execute"
      enabled     = true
      expression  = "true"
      action_parameters = {
        id = "efb7b8c949ac4650a09736fc376e9aee"
        overrides = {
          sensitivity_level = "medium"
          categories = [
            { category = "wordpress", action = "log", enabled = true },
            { category = "joomla", action = "log", enabled = true },
          ]
        }
      }
    },
    {
      description = "Execute OWASP Core Ruleset"
      action      = "execute"
      enabled     = true
      expression  = "true"
      action_parameters = {
        id = "4814384a9e5d4991b9815dcfc25d2f1f"
        overrides = {
          sensitivity_level = "high"
        }
      }
    },
  ]
}

resource "cloudflare_dns_record" "assets_root" {
  zone_id = local.cf_zone_id
  name    = "assets.rbcdemo.ca"
  type    = "CNAME"
  content = "assets-rbcdemo-ca.edgekey.net"
  proxied = false
  ttl     = 1
  comment = "Akamai-primary; CF cutover pending"
}
