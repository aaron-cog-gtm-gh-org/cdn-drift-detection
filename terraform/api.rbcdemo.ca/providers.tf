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
  domain             = "api.rbcdemo.ca"
  akamai_edge        = "api-rbcdemo-ca.edgekey.net"
  origin_host        = "origin-api.rbcdemo.ca"
  cf_zone_id         = "3c4d5e6f708192a3b4c5d6e7f8091a2b"
  akamai_contract_id = "ctr_C-0N7RAC7"
  akamai_group_id    = "grp_98765"
  akamai_product_id  = "prd_Ion"
  akamai_rule_format = "v2023-01-05"
  drift_baseline     = true
}

variable "partner_rate_limit" {
  type        = number
  default     = 100
  description = "Open-banking partner requests per minute"
}
