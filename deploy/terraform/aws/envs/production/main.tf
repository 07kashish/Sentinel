#############################################################################
# Sentinel — production
#
# ESTIMATED ~$700/month. ESTIMATED: no bill for this platform has ever
# existed. MEASURED_AWS_UNIT_ECONOMICS is an open external gate and
# `posture.budget_is_measured` is hardcoded false for the same reason.
#   ALB $16, ECS 3x 1vCPU $180, RDS m7g.large multi-AZ $260,
#   Valkey 2x t4g.medium $100, NAT 3 AZ $96, backup ~$20, KMS $4, rest ~$25.
#
# NOTHING IS WEAKENED HERE. Every flag is at its strong setting, and the ones
# that are irreversible are irreversible on purpose:
#
#   vault lock ON        recovery points cannot be deleted before retention
#                        expires, by anyone, including the account root. This
#                        is what makes a backup survive an attacker holding
#                        admin credentials — which is the threat that makes
#                        backups worth having in a security product.
#   Object Lock 10y      transparency roots undeletable for a decade.
#   WAF BLOCKING         and this is the ONE setting that should not be turned
#                        on here first. Run the pilot in count mode, read the
#                        metrics, then enable. Switching a WAF straight to
#                        blocking on unfamiliar traffic causes an outage, a
#                        rollback, and a permanent reluctance to try again.
#
# THIS CONFIGURATION HAS NEVER BEEN APPLIED.
# -----------------------------------------
# `terraform validate` passes. That is evidence the configuration is coherent
# and it is NOT evidence that it works: no PRODUCTION_SOAK, no
# INDEPENDENT_FAILURE_DOMAIN_DR, no measured unit economics. Applying this is
# the beginning of collecting that evidence, not the end.
#
# ORDER OF OPERATIONS FOR A FIRST APPLY
#   1. apply ../identity first, and stop using a static access key
#   2. build and push an ARM64 image, note its DIGEST
#   3. apply with waf_blocking = false
#   4. set the secret VALUES out of band (see `how_to_set_secrets`)
#   5. run the migration, confirm /health/live
#   6. read the WAF count metrics for a week, then set waf_blocking = true
#   7. start the soak clock
#############################################################################

terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = "Sentinel"
      Environment = "production"
      ManagedBy   = "terraform"
    }
  }
}

variable "region" {
  type    = string
  default = "eu-west-2"
}

variable "image" {
  description = <<-EOT
    Pinned by DIGEST, and there is no default.

    Deliberately required: a production image is a decision, and a default
    here would let an apply succeed against a placeholder. The `validate`
    evidence for this environment is produced with -var, not with a fallback
    nobody chose.
  EOT
  type        = string
}

variable "certificate_arn" {
  description = "ACM certificate. Required in production: `posture.tls_terminated` is checked by scripts/check_terraform_posture.py."
  type        = string
}

variable "cors_origins" {
  description = "Explicit console origins. A wildcard is refused by SENTINEL_ENV=production."
  type        = string
}

variable "alarm_email" {
  description = "Required in production. Without it, alarms fire into a topic nobody is subscribed to."
  type        = string

  validation {
    condition     = var.alarm_email != ""
    error_message = "alarm_email is required in production. An alarm that fires into an unsubscribed SNS topic is not monitoring, and the posture output reports alarms_reach_a_human = false."
  }
}

variable "waf_blocking" {
  description = <<-EOT
    Block, or count.

    FALSE for the first apply, on purpose. Read the count metrics against real
    traffic for a week, then set true. A WAF switched straight to blocking on
    unfamiliar traffic causes an outage and a rollback, after which nobody
    turns it on again.
  EOT
  type        = bool
  default     = false
}

module "sentinel" {
  source = "../../modules/stack"

  name         = "production"
  sentinel_env = "production"

  cidr_block         = "10.44.0.0/16"
  availability_zones = ["${var.region}a", "${var.region}b", "${var.region}c"]

  image           = var.image
  certificate_arn = var.certificate_arn

  # THREE NAT GATEWAYS, one per AZ. $96/month, and the alternative is that
  # losing one AZ takes private egress for all three.
  enable_nat_gateway  = true
  single_nat_gateway  = false
  interface_endpoints = []

  instance_class = "db.m7g.large"
  # Graviton, and NOT burstable. A t-class instance under sustained load
  # exhausts its CPU credits and is then throttled to baseline, which presents
  # as the application hanging rather than as a resource limit.
  allocated_storage_gb     = 200
  max_allocated_storage_gb = 1000
  multi_az                 = true
  backup_retention_days    = 35
  deletion_protection      = true

  cache_node_type     = "cache.t4g.medium"
  cache_replica_count = 1

  task_cpu      = 1024
  task_memory   = 2048
  desired_count = 3
  min_capacity  = 3
  max_capacity  = 12

  cors_origins = var.cors_origins
  # FAIL CLOSED. When the limiter is unreachable, refusing loses availability
  # and allowing loses the limit. For a security control on the authorization
  # path, losing the limit is the worse outcome.
  rate_limit_fail_open = false
  # TRUE. Without it the unbound tool path remains usable and the deployment
  # is only as bound as its call sites happen to be — at which point "Sentinel
  # binds authorization to execution" is a claim about the code rather than
  # about this system.
  require_execution_binding = true
  waf_blocking              = var.waf_blocking

  # TEN YEARS, IRREVERSIBLE. An auditor checking a root from last year needs
  # it still locked, and at ~200 bytes a day a decade is about 0.7 MB.
  evidence_retention_days     = 3650
  artifact_retention_days     = 365
  log_retention_days          = 365
  flow_log_retention_days     = 90
  daily_backup_retention_days = 35
  # TRUE, AND IRREVERSIBLE once the grace window passes. The point of the
  # whole backup module: recovery points that survive an attacker with admin
  # credentials.
  enable_vault_lock = true

  alarm_email           = var.alarm_email
  monthly_budget_usd    = 1200
  estimated_monthly_usd = 700
}

output "alb_dns_name" {
  value = module.sentinel.alb_dns_name
}

output "evidence_bucket" {
  value = module.sentinel.evidence_bucket
}

output "publisher_policy_json" {
  value = module.sentinel.publisher_policy_json
}

output "how_to_set_secrets" {
  value = module.sentinel.how_to_set_secrets
}

output "posture" {
  value = module.sentinel.posture
}

output "cost_notes" {
  value = module.sentinel.cost_notes
}

output "what_this_does_not_prove" {
  description = "Stated in the configuration itself, so it travels with it."
  value = join(" ", [
    "This configuration VALIDATES. It has never been applied.",
    "PRODUCTION_SOAK, INDEPENDENT_FAILURE_DOMAIN_DR and",
    "MEASURED_AWS_UNIT_ECONOMICS are open external gates, and no amount of",
    "Terraform closes any of them. See docs/readiness/GAP_LEDGER.md.",
  ])
}
