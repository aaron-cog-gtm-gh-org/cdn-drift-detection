# ---------- Akamai ----------

resource "akamai_cp_code" "assets" {
  name        = "assets.rbcdemo.ca-cpcode"
  contract_id = local.akamai_contract_id
  group_id    = local.akamai_group_id
  product_id  = local.akamai_product_id
}

resource "akamai_edge_hostname" "assets" {
  product_id    = local.akamai_product_id
  contract_id   = local.akamai_contract_id
  group_id      = local.akamai_group_id
  edge_hostname = local.akamai_edge
  ip_behavior   = "IPV4"
  certificate   = akamai_cp_code.assets.id
}

resource "akamai_property" "assets" {
  name        = "assets.rbcdemo.ca"
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
