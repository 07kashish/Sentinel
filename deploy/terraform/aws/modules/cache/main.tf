#############################################################################
# Sentinel — Valkey (Redis-compatible) for SHARED SECURITY STATE
#
# WHAT THIS COSTS:
#   cache.t4g.micro  single node   ~$12/month  (dev)
#   cache.t4g.small  2 nodes       ~$50/month  (pilot/production)
#
# VALKEY, NOT REDIS OSS. Same wire protocol, and AWS prices Valkey roughly 20%
# below Redis OSS on the same node class. `RedisCache.from_url` speaks the
# protocol, not the brand.
#
# WHY THIS IS NOT OPTIONAL IN ANY MULTI-PROCESS DEPLOYMENT
# --------------------------------------------------------
# The rate limiter, the nonce ledger, distributed locks and session revocation
# are all shared security state. Without a shared store they become
# per-process, and per-process means:
#
#   * N replicas permit N times the configured rate — a limiter that looks
#     correct and is not;
#   * an ExecutionAuthorization nonce can be replayed once per process, so
#     "single use" holds only within one worker.
#
# `sentinel/composition/topology.py` OBSERVES the process count from the
# process table and refuses to start a multi-process deployment without
# SENTINEL_REDIS_URL. That refusal is why this module exists: the alternative
# is a deployment that boots happily and enforces nothing.
#
# ENCRYPTION IN TRANSIT IS ON AND AUTHENTICATION IS REQUIRED. An unauthenticated
# Redis reachable from the application subnet is a store any compromised task
# can flush — and flushing the nonce ledger makes every spent authorization
# replayable.
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

variable "name" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "subnet_ids" {
  description = "Private application subnets. Not the database tier."
  type        = list(string)
}

variable "allowed_security_group_ids" {
  description = "Groups permitted to reach 6379. Groups, never CIDRs."
  type        = list(string)
}

variable "kms_key_arn" {
  type = string
}

variable "secret_kms_key_arn" {
  type = string
}

variable "node_type" {
  type    = string
  default = "cache.t4g.micro"
}

variable "engine_version" {
  type    = string
  default = "7.2"
}

variable "replica_count" {
  description = <<-EOT
    Replicas beyond the primary.

    ZERO IS A REAL CHOICE AND ITS CONSEQUENCE IS SPECIFIC: losing the single
    node loses the nonce ledger, and every authorization spent since the last
    snapshot becomes replayable. Acceptable in dev. In production the failover
    is what stops a node replacement from re-opening single-use authorizations.
  EOT
  type        = number
  default     = 0
}

variable "tags" {
  type    = map(string)
  default = {}
}

locals {
  tags = merge(var.tags, {
    Project   = "Sentinel"
    ManagedBy = "terraform"
    Component = "cache"
  })

  multi_node = var.replica_count > 0
}

resource "aws_elasticache_subnet_group" "this" {
  name       = "sentinel-${var.name}"
  subnet_ids = var.subnet_ids
  tags       = local.tags
}

resource "aws_security_group" "this" {
  name        = "sentinel-${var.name}-cache"
  description = "Valkey, reachable only from named application security groups"
  vpc_id      = var.vpc_id
  tags        = merge(local.tags, { Name = "${var.name}-cache" })
}

resource "aws_vpc_security_group_ingress_rule" "valkey" {
  count = length(var.allowed_security_group_ids)

  security_group_id            = aws_security_group.this.id
  referenced_security_group_id = var.allowed_security_group_ids[count.index]
  description                  = "Valkey from an application workload"
  from_port                    = 6379
  to_port                      = 6379
  ip_protocol                  = "tcp"
}

# THE OTHER HALF OF THE SAME PERMISSION. Security groups are evaluated on
# both ends: the rule above admits the workload here, and this one lets the
# workload's own group leave for this port. The application group permits
# egress to 443 only, so without this rule every connection to the Valkey
# endpoint timed out -- found on the first real deployment of this stack
# (2026-09-24). Owned here, beside the ingress rule it completes, so the two
# cannot drift apart.
resource "aws_vpc_security_group_egress_rule" "valkey_from_workload" {
  count = length(var.allowed_security_group_ids)

  security_group_id            = var.allowed_security_group_ids[count.index]
  referenced_security_group_id = aws_security_group.this.id
  description                  = "Valkey: this workload may reach the valkey group"
  from_port                    = 6379
  to_port                      = 6379
  ip_protocol                  = "tcp"
}

# No egress rule: a cache does not initiate outbound connections.

resource "random_password" "auth" {
  length = 64
  # ElastiCache AUTH tokens permit a restricted punctuation set, and a
  # rejected character produces an error that does not say which one.
  override_special = "!&#$^<>-"
}

resource "aws_elasticache_replication_group" "this" {
  replication_group_id = "sentinel-${var.name}"
  description          = "Sentinel ${var.name} shared security state: rate limits, nonce ledger, locks"

  engine         = "valkey"
  engine_version = var.engine_version
  node_type      = var.node_type
  port           = 6379

  num_cache_clusters = 1 + var.replica_count

  subnet_group_name  = aws_elasticache_subnet_group.this.name
  security_group_ids = [aws_security_group.this.id]

  # Both required. In-transit encryption without an auth token gives an
  # encrypted channel to an unauthenticated store, which is a padlock on an
  # open door.
  transit_encryption_enabled = true
  auth_token                 = random_password.auth.result
  at_rest_encryption_enabled = true
  kms_key_id                 = var.kms_key_arn

  # Only meaningful with a replica; ElastiCache rejects both when there is
  # exactly one node, so they follow the replica count rather than being set
  # unconditionally and failing the apply.
  automatic_failover_enabled = local.multi_node
  multi_az_enabled           = local.multi_node

  maintenance_window = "sun:05:00-sun:06:00"

  # SNAPSHOTS ARE ON, AND THE REASON IS THE NONCE LEDGER.
  #
  # A cache is normally treated as disposable. This one holds spent
  # authorization nonces, so losing it re-opens every authorization issued
  # since the last snapshot for replay. Five days is cheap and bounds that
  # window.
  snapshot_retention_limit = 5
  snapshot_window          = "03:00-04:00"

  auto_minor_version_upgrade = true
  apply_immediately          = false

  tags = merge(local.tags, { Name = "sentinel-${var.name}-cache" })

  lifecycle {
    # The token is rotated out of band, so the ROTATION STRATEGY is ignored
    # with it. Without the second entry, an imported or refreshed group has no
    # recorded strategy, the provider plans `auth_token_update_strategy =
    # ROTATE`, sends a rotation with whatever token state holds, and
    # ElastiCache refuses it -- which stopped the resumed apply on 2026-09-27.
    ignore_changes = [auth_token, auth_token_update_strategy]
  }
}

resource "aws_secretsmanager_secret" "url" {
  name        = "sentinel/${var.name}/redis-url"
  description = "SENTINEL_REDIS_URL. rediss:// with the auth token; the settings parser refuses anything that is not redis:// or rediss://."
  kms_key_id  = var.secret_kms_key_arn

  recovery_window_in_days = 30
  tags                    = local.tags
}

resource "aws_secretsmanager_secret_version" "url" {
  secret_id = aws_secretsmanager_secret.url.id
  # rediss://, with the extra s: transit encryption is on, and a redis:// URL
  # against a TLS-only endpoint fails with a protocol error that reads like the
  # server is down.
  #
  # The token is URL-ENCODED. Its permitted set includes `#`, which starts a
  # URL fragment: the first real deployment generated one, the application
  # parsed a URL with no host, could not reach the limiter, and -- failing
  # closed, correctly -- answered 429 to every request.
  secret_string = format(
    "rediss://:%s@%s:%d",
    urlencode(random_password.auth.result),
    aws_elasticache_replication_group.this.primary_endpoint_address,
    aws_elasticache_replication_group.this.port,
  )

  # SET ONCE, like the auth token on the replication group above. Rotation
  # is applied to both through the service, never as a Terraform diff on one
  # (the database module holds to the same rule, for the same reason).
  lifecycle {
    ignore_changes = [secret_string]
  }
}

output "primary_endpoint" {
  value = aws_elasticache_replication_group.this.primary_endpoint_address
}

output "security_group_id" {
  value = aws_security_group.this.id
}

output "url_secret_arn" {
  value = aws_secretsmanager_secret.url.arn
}

output "survives_node_loss" {
  description = <<-EOT
    Whether losing a node keeps the nonce ledger.

    Exported because it is a security property and not merely an availability
    one: with a single node, a replacement re-opens every authorization spent
    since the last snapshot for replay.
  EOT
  value       = local.multi_node
}
