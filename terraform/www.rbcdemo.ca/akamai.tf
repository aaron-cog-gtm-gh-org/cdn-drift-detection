# ---------- Akamai ----------

resource "akamai_cp_code" "www" {
  name        = "www.rbcdemo.ca-cpcode"
  contract_id = local.akamai_contract_id
  group_id    = local.akamai_group_id
  product_id  = local.akamai_product_id
}

resource "akamai_edge_hostname" "www" {
  product_id    = local.akamai_product_id
  contract_id   = local.akamai_contract_id
  group_id      = local.akamai_group_id
  edge_hostname = local.akamai_edge
  ip_behavior   = "IPV4"
  certificate   = akamai_cp_code.www.id
}

resource "akamai_property" "www" {
  name        = "www.rbcdemo.ca"
  contract_id = local.akamai_contract_id
  group_id    = local.akamai_group_id
  product_id  = local.akamai_product_id
  rule_format = local.akamai_rule_format

  dynamic "hostnames" {
    for_each = jsondecode(file("${path.module}/akamai/hostnames.json")).hostnames.items
    content {
      cname_from             = hostnames.value.cnameFrom
      cname_to               = hostnames.value.cnameTo
      cert_provisioning_type = hostnames.value.certProvisioningType
    }
  }

  rules = file("${path.module}/akamai/rules.json")
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
  appsec_config = jsondecode(file("${path.module}/akamai/appsec.json"))
}

resource "akamai_appsec_configuration" "www" {
  name        = "www.rbcdemo.ca security config"
  description = "WAF config for www.rbcdemo.ca"
  contract_id = local.akamai_contract_id
  group_id    = local.akamai_group_id
  host_names  = ["www.rbcdemo.ca"]
}

resource "akamai_appsec_security_policy" "www_default" {
  config_id              = akamai_appsec_configuration.www.config_id
  security_policy_name   = "Default policy"
  security_policy_prefix = "RB1"
}

resource "akamai_appsec_rate_policy" "www" {
  for_each    = { for p in local.appsec_config.ratePolicies.items : tostring(p.id) => p }
  config_id   = akamai_appsec_configuration.www.config_id
  rate_policy = jsonencode(each.value)
}
