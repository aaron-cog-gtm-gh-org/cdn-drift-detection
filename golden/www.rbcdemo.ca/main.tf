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
  domain         = "www.rbcdemo.ca"
  akamai_edge    = "www-rbcdemo-ca.edgekey.net"
  origin_host    = "origin-www.rbcdemo.ca"
  cf_zone_id     = "1a2b3c4d5e6f708192a3b4c5d6e7f801"
  drift_baseline = true
}

# ---------- Akamai ----------

resource "akamai_cp_code" "www" {
  name        = "www.rbcdemo.ca-cpcode"
  contract_id = "ctr_C-0N7RAC7"
  group_id    = "grp_98765"
  product_id  = "prd_Ion"
}

resource "akamai_edge_hostname" "www" {
  product_id    = "prd_Ion"
  contract_id   = "ctr_C-0N7RAC7"
  group_id      = "grp_98765"
  edge_hostname = "www-rbcdemo-ca.edgekey.net"
  ip_behavior   = "IPV4"
  certificate   = akamai_cp_code.www.id
}

data "akamai_property_rules_template" "www" {
  template_file = "${path.module}/rules/rules.json"
}

resource "akamai_property" "www" {
  name        = "www.rbcdemo.ca"
  contract_id = "ctr_C-0N7RAC7"
  group_id    = "grp_98765"
  product_id  = "prd_Ion"
  rule_format = "v2023-01-05"
  hostnames {
    cname_from             = "www.rbcdemo.ca"
    cname_to               = akamai_edge_hostname.www.edge_hostname
    cert_provisioning_type = "CPS_MANAGED"
  }
  rules = data.akamai_property_rules_template.www.json
}

resource "akamai_property_activation" "www_staging" {
  property_id                    = akamai_property.www.id
  network                        = "STAGING"
  version                        = akamai_property.www.latest_version
  auto_acknowledge_rule_warnings = true
  compliance_record {
    noncompliance_reason_none {}
  }
}

resource "akamai_property_activation" "www_production" {
  property_id                    = akamai_property.www.id
  network                        = "PRODUCTION"
  version                        = akamai_property.www.latest_version
  auto_acknowledge_rule_warnings = true
  compliance_record {
    noncompliance_reason_none {}
  }
}

locals {
  appsec_config = jsondecode(file("${path.module}/appsec/security-config.json"))
}

resource "akamai_appsec_configuration" "www" {
  name        = "www.rbcdemo.ca security config"
  description = "WAF config for www.rbcdemo.ca"
  contract_id = "ctr_C-0N7RAC7"
  group_id    = "grp_98765"
  host_names  = ["www.rbcdemo.ca"]
}

resource "akamai_appsec_security_policy" "www_default" {
  config_id              = akamai_appsec_configuration.www.config_id
  security_policy_name   = "Default policy"
  security_policy_prefix = "RB1"
}

resource "akamai_appsec_rate_policy" "www_global" {
  config_id   = akamai_appsec_configuration.www.config_id
  rate_policy = jsonencode({ for p in local.appsec_config.ratePolicies.items : p.id => p }["rp_9001"])
}


# ---------- Cloudflare ----------

resource "cloudflare_zone_setting" "www_ssl" {
  zone_id    = local.cf_zone_id
  setting_id = "ssl"
  value      = "strict"
}

resource "cloudflare_zone_setting" "www_min_tls_version" {
  zone_id    = local.cf_zone_id
  setting_id = "min_tls_version"
  value      = "1.2"
}

resource "cloudflare_zone_setting" "www_always_use_https" {
  zone_id    = local.cf_zone_id
  setting_id = "always_use_https"
  value      = "on"
}

resource "cloudflare_zone_setting" "www_http2" {
  zone_id    = local.cf_zone_id
  setting_id = "http2"
  value      = "on"
}

resource "cloudflare_zone_setting" "www_brotli" {
  zone_id    = local.cf_zone_id
  setting_id = "brotli"
  value      = "on"
}

resource "cloudflare_ruleset" "www_managed_waf" {
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
          sensitivity_level = "medium"
        }
      }
    },
  ]
}

resource "cloudflare_dns_record" "www_root" {
  zone_id = local.cf_zone_id
  name    = "www.rbcdemo.ca"
  type    = "A"
  content = "203.0.113.10"
  proxied = true
  ttl     = 1
  comment = "CF-primary origin"
}
