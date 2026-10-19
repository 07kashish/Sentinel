#############################################################################
# Sentinel — dev
#
# ESTIMATED ~$55/month. ESTIMATED: no bill for this platform exists, which is
# what MEASURED_AWS_UNIT_ECONOMICS records as an open external gate.
#   ALB $16 (the floor — bills hourly whether called or not), ECS $15,
#   RDS $12, Valkey $12, KMS $4, NAT $0, interface endpoints $0.
#
# WHAT DEV GIVES UP, as a list rather than as defaults nobody chose:
#   no NAT           tasks cannot reach the public internet at all
#   no interface     ...and cannot reach ECR or Secrets Manager either, so a
#   endpoints        task cannot actually start here without NAT. Stated
#                    because it is a real limitation, not a subtlety.
#   single AZ        an AZ loss takes the environment down
#   no cache replica losing the node re-opens every authorization nonce spent
#                    since the last snapshot
#   no TLS           the listener serves plain HTTP
#   WAF counting     nothing is blocked
#   no vault lock    backups are deletable
#   no deletion      `terraform destroy` works, which is the point of dev
#   protection
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

  # NO BACKEND BLOCK, deliberately. A committed backend makes `terraform init`
  # in a checkout reach for state that may not be this operator's. Configure
  # it per operator with `-backend-config`; `terraform validate` needs no
  # backend at all, which is what makes plan-only validation possible in CI
  # with no credentials.
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = "Sentinel"
      Environment = "dev"
      ManagedBy   = "terraform"
    }
  }
}

variable "region" {
  type    = string
  default = "eu-west-2"
}

variable "image" {
  description = "Pinned by digest. The placeholder below lets validate and plan run before an image exists; an apply with it fails to pull, which is correct for a value nobody set."
  type        = string
  default     = "public.ecr.aws/docker/library/python@sha256:0000000000000000000000000000000000000000000000000000000000000000"
}

variable "alarm_email" {
  type    = string
  default = ""
}

module "sentinel" {
  source = "../../modules/stack"

  name         = "dev"
  sentinel_env = "development"

  cidr_block         = "10.42.0.0/16"
  availability_zones = ["${var.region}a", "${var.region}b"]

  image           = var.image
  certificate_arn = ""

  # OFF. ~$32/month per AZ before any traffic, which on a $55 environment is
  # over half the bill.
  enable_nat_gateway = false
  # Empty: $7.20/month each per AZ, and six across two AZs would cost more
  # than everything else here combined.
  interface_endpoints = []

  instance_class       = "db.t4g.micro"
  allocated_storage_gb = 20
  # A tight ceiling: a runaway ingest loop should hit a wall at 40 GB rather
  # than growing quietly and arriving as a bill.
  max_allocated_storage_gb = 40
  multi_az                 = false
  backup_retention_days    = 7
  # The one setting that must NOT be copied to production.
  deletion_protection = false

  cache_node_type     = "cache.t4g.micro"
  cache_replica_count = 0

  desired_count = 1
  min_capacity  = 1
  max_capacity  = 2

  cors_origins = "http://localhost:5173"
  # Fail OPEN in dev: a developer without a reachable limiter should not be
  # locked out of their own service. The asymmetry with production is the
  # whole reason the production case must be explicit rather than inherited.
  rate_limit_fail_open      = true
  require_execution_binding = false
  waf_blocking              = false

  # SHORT, AND STILL IRREVERSIBLE. Object Lock COMPLIANCE cannot be shortened,
  # so even here these objects are undeletable for a year. Not zero, because a
  # dev environment that cannot exercise the real Object Lock path cannot catch
  # the bugs in it.
  evidence_retention_days     = 365
  artifact_retention_days     = 30
  log_retention_days          = 14
  flow_log_retention_days     = 7
  daily_backup_retention_days = 7
  enable_vault_lock           = false

  alarm_email           = var.alarm_email
  monthly_budget_usd    = 100
  estimated_monthly_usd = 55
}

output "alb_dns_name" {
  value = module.sentinel.alb_dns_name
}

output "evidence_bucket" {
  value = module.sentinel.evidence_bucket
}

output "posture" {
  value = module.sentinel.posture
}

output "cost_notes" {
  value = module.sentinel.cost_notes
}
