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
  domain             = "online.rbcdemo.ca"
  akamai_edge        = "online-rbcdemo-ca.edgekey.net"
  origin_host        = "origin-online.rbcdemo.ca"
  cf_zone_id         = "2b3c4d5e6f708192a3b4c5d6e7f8091a"
  akamai_contract_id = "ctr_C-0N7RAC7"
  akamai_group_id    = "grp_98765"
  akamai_product_id  = "prd_Ion"
  akamai_rule_format = "v2023-01-05"
  drift_baseline     = true
}
