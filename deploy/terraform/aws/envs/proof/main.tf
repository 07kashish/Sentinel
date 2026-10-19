#############################################################################
# Sentinel — proof
#
# A free-plan account refuses the `pilot` sizing (multi-AZ db.t4g.small, two
# cache nodes; it refused a t4g.large the same way on 2026-09-20). This root
# applies the SAME stack module with free-tier-eligible sizes for a few
# hours, so that what is proven is the wiring — managed PostgreSQL, managed
# cache, ALB, S3 with KMS, Secrets Manager injection, task roles, two Fargate
# tasks in two AZs — and what is NOT proven (AZ-loss survival) is stated in
# the evidence that cites this file.
#
# Every weakening relative to pilot is a size or a retention, never a
# security setting: production mode, execution binding required, rate limit
# fails closed, evidence sealed. TLS is off only because no domain exists,
# and `posture` reports it.
#
# NOTHING HERE IS APPLIED BY THIS REPOSITORY. Applied by hand on 2026-09-24
# and destroyed the same day; see docs/current/evidence/.
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
      Environment = "proof"
      ManagedBy   = "terraform"
    }
  }
}

variable "region" {
  type    = string
  default = "ap-south-1"
}

variable "image" {
  description = "Pinned by digest; supplied at apply time from the ECR push."
  type        = string
  default     = "public.ecr.aws/docker/library/python@sha256:0000000000000000000000000000000000000000000000000000000000000000"
}

variable "cors_origins" {
  type    = string
  default = "https://console.example.com"
}

variable "certificate_arn" {
  description = "Issued ACM certificate in this region. A customer pilot requires the matching HTTPS domain."
  type        = string
  default     = ""
}

variable "mcp_proxy" {
  description = "Explicitly reviewed upstreams only; remain off until HTTPS and enrollment are verified."
  type = object({
    enabled       = bool
    allowed_hosts = set(string)
  })
  default = { enabled = false, allowed_hosts = [] }
}

variable "advisor" {
  description = "Advisory model (OpenAI-compatible base URL + model). Off unless supplied at apply time; the key goes into the advisor-token secret by hand, never here."
  type = object({
    endpoint = string
    model    = string
  })
  default = { endpoint = "", model = "" }
}

variable "brain_host" {
  description = "The pipeline replica on a host where the owner signs in to their advisor CLI. Off unless supplied at apply time."
  type = object({
    enabled       = bool
    instance_type = string
    model         = string
  })
  default = { enabled = false, instance_type = "t4g.small", model = "" }
}

module "sentinel" {
  source = "../../modules/stack"

  name         = "proof"
  sentinel_env = "production"

  cidr_block         = "10.44.0.0/16"
  availability_zones = ["${var.region}a", "${var.region}b"]

  image           = var.image
  certificate_arn = var.certificate_arn
  mcp_proxy       = var.mcp_proxy
  advisor         = var.advisor
  brain_host      = var.brain_host

  enable_nat_gateway  = true
  single_nat_gateway  = true
  interface_endpoints = []

  # Free-tier-eligible sizes. Single AZ: AZ-loss survival is NOT proven here.
  instance_class           = "db.t4g.micro"
  allocated_storage_gb     = 20
  max_allocated_storage_gb = 40
  multi_az                 = false
  backup_retention_days    = 1     # the account's free plan refuses more (FreeTierRestrictionError on 7); AWS Backup below keeps 7 daily
  deletion_protection      = true  # a demo somebody shares is a database somebody can delete by mistake

  cache_node_type     = "cache.t4g.micro"
  cache_replica_count = 0

  task_cpu      = 512
  task_memory   = 1024
  desired_count = 2
  min_capacity  = 2
  max_capacity  = 2

  cors_origins              = var.cors_origins
  rate_limit_fail_open      = false
  require_execution_binding = true
  waf_blocking              = false

  # One day is the shortest COMPLIANCE retention the module allows; the
  # evidence bucket can therefore be emptied and removed the day after.
  evidence_retention_days     = 1
  artifact_retention_days     = 7
  log_retention_days          = 7
  flow_log_retention_days     = 7
  daily_backup_retention_days = 7
  enable_vault_lock           = false

  # A shareable, read-only console: the published key is a viewer key in a
  # separate `demo` tenant. Nothing else in this environment changes.
  console_demo_enabled = true
  root_publish_tenants = ["demo"] # the demo tenant's proofs become independently verifiable

  alarm_email           = ""
  monthly_budget_usd    = 20
  estimated_monthly_usd = 5
}

output "alb_dns_name" {
  value = module.sentinel.alb_dns_name
}

output "evidence_bucket" {
  value = module.sentinel.evidence_bucket
}

output "database_endpoint" {
  value = module.sentinel.database_endpoint
}

output "cache_endpoint" {
  value = module.sentinel.cache_endpoint
}

output "task_role_arn" {
  value = module.sentinel.task_role_arn
}

output "posture" {
  value = module.sentinel.posture
}

output "how_to_set_secrets" {
  value = module.sentinel.how_to_set_secrets
}
