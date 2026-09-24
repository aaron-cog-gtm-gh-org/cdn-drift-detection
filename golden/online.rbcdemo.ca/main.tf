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
  domain         = "online.rbcdemo.ca"
  akamai_edge    = "online-rbcdemo-ca.edgekey.net"
  origin_host    = "origin-online.rbcdemo.ca"
  cf_zone_id     = "2b3c4d5e6f708192a3b4c5d6e7f8091a"
  drift_baseline = true
}

# ---------- Akamai ----------

resource "akamai_cp_code" "online" {
  name        = "online.rbcdemo.ca-cpcode"
  contract_id = "ctr_C-0N7RAC7"
  group_id    = "grp_98765"
  product_id  = "prd_Ion"
}

resource "akamai_edge_hostname" "online" {
  product_id    = "prd_Ion"
  contract_id   = "ctr_C-0N7RAC7"
  group_id      = "grp_98765"
  edge_hostname = "online-rbcdemo-ca.edgekey.net"
  ip_behavior   = "IPV4"
  certificate   = akamai_cp_code.online.id
}

data "akamai_property_rules_template" "online" {
  template_file = "${path.module}/rules/rules.json"
}

resource "akamai_property" "online" {
  name        = "online.rbcdemo.ca"
  contract_id = "ctr_C-0N7RAC7"
  group_id    = "grp_98765"
  product_id  = "prd_Ion"
  rule_format = "v2023-01-05"
  hostnames {
    cname_from             = "online.rbcdemo.ca"
    cname_to               = akamai_edge_hostname.online.edge_hostname
    cert_provisioning_type = "CPS_MANAGED"
  }
  rules = data.akamai_property_rules_template.online.json
}

resource "akamai_property_activation" "online_staging" {
  property_id                    = akamai_property.online.id
  network                        = "STAGING"
  version                        = akamai_property.online.latest_version
  auto_acknowledge_rule_warnings = true
  compliance_record {
    noncompliance_reason_none {}
  }
}

resource "akamai_property_activation" "online_production" {
  property_id                    = akamai_property.online.id
  network                        = "PRODUCTION"
  version                        = akamai_property.online.latest_version
  auto_acknowledge_rule_warnings = true
  compliance_record {
    noncompliance_reason_none {}
  }
}

locals {
  appsec_config = jsondecode(file("${path.module}/appsec/security-config.json"))
}

resource "akamai_appsec_configuration" "online" {
  name        = "online.rbcdemo.ca security config"
  description = "WAF config for online.rbcdemo.ca"
  contract_id = "ctr_C-0N7RAC7"
  group_id    = "grp_98765"
  host_names  = ["online.rbcdemo.ca"]
}

resource "akamai_appsec_security_policy" "online_default" {
  config_id              = akamai_appsec_configuration.online.config_id
  security_policy_name   = "Default policy"
  security_policy_prefix = "RB1"
}

resource "akamai_appsec_rate_policy" "online_global" {
  config_id   = akamai_appsec_configuration.online.config_id
  rate_policy = jsonencode({ for p in local.appsec_config.ratePolicies.items : p.id => p }[9001])
}

resource "akamai_appsec_rate_policy" "online_login" {
  config_id   = akamai_appsec_configuration.online.config_id
  rate_policy = jsonencode({ for p in local.appsec_config.ratePolicies.items : p.id => p }[9002])
}


# ---------- Cloudflare ----------

resource "cloudflare_zone_setting" "online_ssl" {
  zone_id    = local.cf_zone_id
  setting_id = "ssl"
  value      = "strict"
}

resource "cloudflare_zone_setting" "online_min_tls_version" {
  zone_id    = local.cf_zone_id
  setting_id = "min_tls_version"
  value      = "1.2"
}

resource "cloudflare_zone_setting" "online_always_use_https" {
  zone_id    = local.cf_zone_id
  setting_id = "always_use_https"
  value      = "on"
}

resource "cloudflare_zone_setting" "online_http2" {
  zone_id    = local.cf_zone_id
  setting_id = "http2"
  value      = "on"
}

resource "cloudflare_zone_setting" "online_brotli" {
  zone_id    = local.cf_zone_id
  setting_id = "brotli"
  value      = "on"
}

resource "cloudflare_ruleset" "online_managed_waf" {
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

resource "cloudflare_dns_record" "online_root" {
  zone_id = local.cf_zone_id
  name    = "online.rbcdemo.ca"
  type    = "CNAME"
  content = "online-rbcdemo-ca.edgekey.net"
  proxied = false
  ttl     = 1
  comment = "Akamai-primary; CF cutover pending"
}
