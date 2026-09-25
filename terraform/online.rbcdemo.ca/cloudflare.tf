# ---------- Cloudflare ----------

resource "cloudflare_zone_setting" "this" {
  for_each   = jsondecode(file("${path.module}/cloudflare/zone-settings.json"))
  zone_id    = local.cf_zone_id
  setting_id = each.key
  value      = each.value
}

resource "cloudflare_ruleset" "this" {
  for_each = { for r in jsondecode(file("${path.module}/cloudflare/rulesets.json")) : r.name => r }

  zone_id     = local.cf_zone_id
  name        = each.value.name
  kind        = each.value.kind
  phase       = each.value.phase
  description = try(each.value.description, null)

  dynamic "rules" {
    for_each = try(each.value.rules, [])
    content {
      action            = try(rules.value.action, null)
      enabled           = try(rules.value.enabled, null)
      expression        = try(rules.value.expression, null)
      description       = try(rules.value.description, null)
      action_parameters = try(rules.value.action_parameters, null)
      ratelimit         = try(rules.value.ratelimit, null)
      logging           = try(rules.value.logging, null)
    }
  }
}

resource "cloudflare_dns_record" "this" {
  for_each = { for r in jsondecode(file("${path.module}/cloudflare/dns-records.json")) : "${r.type}/${r.name}" => r }

  zone_id  = local.cf_zone_id
  name     = each.value.name
  type     = each.value.type
  content  = each.value.content
  proxied  = each.value.proxied
  ttl      = each.value.ttl
  comment  = try(each.value.comment, null)
  priority = try(each.value.priority, null)
}
