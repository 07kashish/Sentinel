#############################################################################
# Sentinel — stack outputs
#
# `posture` is the important one. It exports what the environment actually
# GUARANTEES as machine-readable data, so a readiness check reads it rather
# than a human inferring a security posture from a variables file.
#
# Every field is a fact about this configuration and several are deliberately
# unflattering. An environment that reports `waf_blocking = false` and
# `restore_verified = false` is telling the truth about itself, which is the
# only way a posture output is worth having — one that reported only good news
# would be a badge rather than a check.
#############################################################################

output "alb_dns_name" {
  value = module.ecs.alb_dns_name
}

output "evidence_bucket" {
  value = module.storage.evidence_bucket
}

output "artifact_bucket" {
  value = module.storage.artifact_bucket
}

output "database_endpoint" {
  value = module.database.endpoint
}

output "cache_endpoint" {
  value = module.cache.primary_endpoint
}

output "queue_urls" {
  value = module.queue.queue_urls
}

output "task_role_arn" {
  value = module.ecs.task_role_arn
}

output "alarm_topic_arn" {
  value = module.observability.alarm_topic_arn
}

output "publisher_policy_json" {
  description = "The two-action policy for the transparency publisher. See docs/TRANSPARENCY_SINK.md."
  value       = module.storage.publisher_policy_json
}

output "how_to_set_secrets" {
  description = "The out-of-band step, printed so it is not folklore. This module does not set secret VALUES."
  value       = module.secrets.how_to_set_a_value
}

output "posture" {
  description = <<-EOT
    What this environment does and does not guarantee, as data.

    Read by scripts/check_terraform_posture.py, which refuses a production
    environment whose posture contradicts its name — so "production" cannot
    quietly ship with the WAF counting and the backups deletable.
  EOT
  value = {
    environment  = var.name
    sentinel_env = var.sentinel_env

    # Transport and perimeter
    tls_terminated  = module.ecs.listener_is_encrypted
    waf_blocking    = module.waf.is_blocking
    internet_egress = module.network.has_internet_egress

    # Survivability
    survives_az_loss           = var.multi_az
    cache_survives_node_loss   = module.cache.survives_node_loss
    backups_survive_compromise = module.backup.is_locked
    pitr_window_days           = module.database.pitr_window_days

    # Enforcement
    execution_binding_required  = var.require_execution_binding
    rate_limit_fails_open       = var.rate_limit_fail_open
    database_deletion_protected = var.deletion_protection

    # Honesty flags: each is a constant false, or reads a value that cannot be
    # satisfied from inside this repository.
    restore_verified     = module.backup.restore_is_verified
    budget_is_measured   = module.budgets.limit_is_measured
    alarms_reach_a_human = module.observability.alarms_reach_a_human
  }
}

output "estimated_monthly_usd" {
  description = <<-EOT
    ESTIMATED, not measured.

    No bill for this platform exists. MEASURED_AWS_UNIT_ECONOMICS is an open
    external gate, and `budget_is_measured` in the posture above is hardcoded
    false for the same reason. Do not quote this as a projection.
  EOT
  value       = var.estimated_monthly_usd
}

output "cost_notes" {
  description = "Where the money actually goes, so a reduction targets the right thing."
  value = {
    alb_floor_usd          = 16
    nat_usd                = module.network.monthly_nat_cost_estimate_usd
    kms_usd                = module.kms.monthly_cost_estimate_usd
    interface_endpoint_usd = length(var.interface_endpoints) * 7.2 * length(var.availability_zones)
    note                   = "The ALB bills hourly whether or not anything calls it, which is why an idle environment is not free. NAT is the largest single lever."
  }
}

output "brain_host" {
  description = "The pipeline replica's instance and what its owner still has to do on it. Null when there is none."
  value = var.brain_host.enabled ? {
    instance_id     = module.brain_host[0].instance_id
    cli_directory   = module.brain_host[0].cli_directory
    sign_in_command = module.brain_host[0].sign_in_command
  } : null
}
