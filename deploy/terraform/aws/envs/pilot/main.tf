#############################################################################
# Sentinel — pilot
#
# ESTIMATED ~$220/month. ESTIMATED: no bill exists, and
# MEASURED_AWS_UNIT_ECONOMICS is an open external gate.
#   ALB $16, ECS 2 tasks $60, RDS t4g.small multi-AZ $50, Valkey 2 nodes $50,
#   NAT single $32, interface endpoints $0 (NAT covers it), KMS $4, rest ~$8.
#
# WHAT PILOT IS FOR
# -----------------
# A design partner's traffic against a configuration that behaves like
# production. Anything weakened here for cost is a thing the pilot cannot
# tell you about production, so the weakenings are few and named:
#
#   single NAT       one AZ's NAT serves all three. Cheaper by $64/month and
#                    a single point of failure for private egress. Acceptable
#                    because a pilot outage is a conversation, not an SLA
#                    breach.
#   WAF counting     still count-only. THIS IS THE POINT OF A PILOT: the
#                    false-positive rate against a real partner's traffic is
#                    what you cannot learn any other way, and switching to
#                    blocking before you have it means blocking the partner.
#   no vault lock    backups deletable, because a pilot that ends leaves
#                    undeletable recovery points otherwise.
#
# WHAT IT DOES NOT WEAKEN
#   multi-AZ database, a cache replica, TLS, execution binding, fail-CLOSED
#   rate limiting, deletion protection. Each of those changes application
#   behaviour, and a pilot that behaves differently from production is a pilot
#   that validates nothing.
#
# NOTHING HERE IS APPLIED BY THIS REPOSITORY.
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
      Environment = "pilot"
      ManagedBy   = "terraform"
    }
  }
}

variable "region" {
  type    = string
  default = "eu-west-2"
}

variable "image" {
  description = "Pinned by digest."
  type        = string
  default     = "public.ecr.aws/docker/library/python@sha256:0000000000000000000000000000000000000000000000000000000000000000"
}

variable "certificate_arn" {
  description = "ACM certificate. Empty serves plain HTTP, which `posture` reports — a pilot partner should not be sending agent events over HTTP."
  type        = string
  default     = ""
}

variable "cors_origins" {
  description = "The partner's console origin. Explicit, never a wildcard: SENTINEL_ENV=production refuses one on a credentialed API."
  type        = string
  default     = "https://console.example.com"
}

variable "alarm_email" {
  type    = string
  default = ""
}

module "sentinel" {
  source = "../../modules/stack"

  name = "pilot"
  # PRODUCTION, not staging. A pilot that sets development skips the preflight
  # requirements and therefore does not test what production will do.
  sentinel_env = "production"

  cidr_block         = "10.43.0.0/16"
  availability_zones = ["${var.region}a", "${var.region}b", "${var.region}c"]

  image           = var.image
  certificate_arn = var.certificate_arn

  # ON, single. A pilot needs to reach a partner's OIDC issuer and any
  # external endpoint they configure. One NAT rather than three: $32 instead
  # of $96, at the cost of a single point of failure for private egress.
  enable_nat_gateway = true
  single_nat_gateway = true
  # Empty because NAT already provides the path; adding interface endpoints on
  # top would be paying twice for the same reachability.
  interface_endpoints = []

  instance_class           = "db.t4g.small"
  allocated_storage_gb     = 50
  max_allocated_storage_gb = 200
  # TRUE. Not weakened: an AZ loss during a pilot is exactly the event a
  # partner will ask about afterwards.
  multi_az              = true
  backup_retention_days = 14
  deletion_protection   = true

  cache_node_type = "cache.t4g.small"
  # ONE REPLICA. Not weakened, and the reason is a security property rather
  # than availability: with a single node, a replacement re-opens every
  # authorization nonce spent since the last snapshot for replay.
  cache_replica_count = 1

  task_cpu      = 1024
  task_memory   = 2048
  desired_count = 2
  min_capacity  = 2
  max_capacity  = 6

  cors_origins = var.cors_origins
  # FAIL CLOSED. A pilot that loses its limiter should refuse rather than
  # serve unlimited, because the partner is watching how it behaves under
  # failure and that is the honest answer.
  rate_limit_fail_open = false
  # TRUE. The binding is the thing a design partner is being asked to trust,
  # so the pilot has to actually enforce it. Requires call sites to pass an
  # authorization — see docs/EXECUTION_TRUST_ARCHITECTURE.md.
  require_execution_binding = true
  # COUNT MODE, and this is deliberate rather than a cost saving. The
  # false-positive rate against a real partner's traffic shape cannot be
  # learned any other way, and switching to blocking before you have it means
  # blocking the partner.
  waf_blocking = false

  evidence_retention_days     = 3650
  artifact_retention_days     = 180
  log_retention_days          = 90
  flow_log_retention_days     = 30
  daily_backup_retention_days = 35
  # FALSE, for one reason only: a pilot that ends otherwise leaves recovery
  # points nobody can delete for a year.
  enable_vault_lock = false

  alarm_email           = var.alarm_email
  monthly_budget_usd    = 400
  estimated_monthly_usd = 220
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
