#############################################################################
# Sentinel — the whole stack, wired once
#
# The twelve modules and the wires between them. Every environment gets the
# same wiring; `variables.tf` holds what they differ on.
#
# NOTHING HERE IS APPLIED BY THIS REPOSITORY. `terraform validate` and
# `terraform plan` are the evidence this configuration is coherent. `apply`
# creates billable resources and is an operator decision — CI holds no
# credentials that could.
#
# ORDER OF DEPENDENCY, since Terraform's graph is not obvious from reading:
#   kms  ->  network, storage, secrets, queue, observability
#   network + observability  ->  ecs
#   ecs (task security group) ->  database, cache
#   ecs (alb arn)             ->  waf
#   database                  ->  backup
#
# The ecs module comes BEFORE database and cache on purpose. It owns the task
# security group, and the database and cache take a list of GROUPS rather than
# CIDRs — a CIDR rule stays correct-looking while the subnet it names gains new
# occupants, where a group rule names the workload.
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

data "aws_region" "current" {}

module "kms" {
  source = "../kms"
  name   = var.name
}

module "network" {
  source = "../network"

  name               = var.name
  cidr_block         = var.cidr_block
  availability_zones = var.availability_zones

  enable_nat_gateway  = var.enable_nat_gateway
  single_nat_gateway  = var.single_nat_gateway
  interface_endpoints = var.interface_endpoints

  flow_log_retention_days = var.flow_log_retention_days
  log_kms_key_arn         = module.kms.key_arns["logs"]
}

module "storage" {
  source = "../storage"

  name                  = var.name
  evidence_kms_key_arn  = module.kms.key_arns["evidence"]
  artifacts_kms_key_arn = module.kms.key_arns["data"]

  evidence_retention_days = var.evidence_retention_days
  artifact_retention_days = var.artifact_retention_days
}

module "secrets" {
  source = "../secrets"

  name        = var.name
  kms_key_arn = module.kms.key_arns["secrets"]

  extra_secrets = merge(
    var.advisor.endpoint != "" ? {
      advisor-token = "SENTINEL_ADVISOR_TOKEN: the advisory model provider's API key. Advisory only; the service refuses to start while this is empty."
    } : {},
  )
}

module "queue" {
  source = "../queue"

  name        = var.name
  kms_key_arn = module.kms.key_arns["data"]
}

module "observability" {
  source = "../observability"

  name           = var.name
  retention_days = var.log_retention_days
  kms_key_arn    = module.kms.key_arns["logs"]
  alarm_email    = var.alarm_email

  dlq_names        = module.queue.dlq_names
  ecs_cluster_name = module.ecs.cluster_name
  ecs_service_name = module.ecs.service_name
  db_instance_id   = "sentinel-${var.name}"

  # The ALB's CloudWatch dimension is the SUFFIX of its ARN, not the ARN. A
  # full ARN here produces alarms that never fire, in INSUFFICIENT_DATA
  # forever, which reads as broken monitoring rather than a wrong value.
  alb_arn_suffix = module.ecs.alb_arn_suffix
  alb_alarms     = true
}

module "ecs" {
  source = "../ecs"

  name               = var.name
  vpc_id             = module.network.vpc_id
  public_subnet_ids  = module.network.public_subnet_ids
  private_subnet_ids = module.network.private_subnet_ids

  image = var.image

  task_cpu      = var.task_cpu
  task_memory   = var.task_memory
  desired_count = var.desired_count
  min_capacity  = var.min_capacity
  max_capacity  = var.max_capacity

  certificate_arn = var.certificate_arn

  log_group_name     = module.observability.log_group_name
  log_kms_key_arn    = module.kms.key_arns["logs"]
  secret_kms_key_arn = module.kms.key_arns["secrets"]

  environment = {
    SENTINEL_ENV = var.sentinel_env

    # BOTH STATED IN EVERY ENVIRONMENT, including development.
    #
    # Production refuses to start without them, and a dev environment that
    # does not set the same variables cannot catch a missing one. That is not
    # hypothetical: `test_a_production_manifest_supplies_what_production_
    # demands` caught exactly this omission in the Helm chart after these
    # requirements were added.
    SENTINEL_RATE_LIMIT_FAIL_OPEN      = tostring(var.rate_limit_fail_open)
    SENTINEL_REQUIRE_EXECUTION_BINDING = tostring(var.require_execution_binding)

    SENTINEL_CORS_ORIGINS = var.cors_origins

    # ENFORCE, not advise. Without these a verdict that says "stop" is a
    # log line and the tool runs; the Helm chart states both, and a stack
    # that inherited the advisory default would deploy a gateway that gates
    # nothing. Found by the first real deployment of this stack (2026-09-24).
    SENTINEL_PROTECT_ENFORCE         = "true"
    SENTINEL_PROTECTION_MODE         = "protect"
    SENTINEL_MCP_PROXY_ENABLED       = tostring(var.mcp_proxy.enabled)
    SENTINEL_MCP_PROXY_ALLOWED_HOSTS = join(",", sort(tolist(var.mcp_proxy.allowed_hosts)))

    # ADVISORY model, when one is named. Both empty means "no advisor", which
    # the service states in every evidence record rather than guessing.
    SENTINEL_ADVISOR_ENDPOINT = var.advisor.endpoint
    SENTINEL_ADVISOR_MODEL    = var.advisor.model

    # Zero when a brain host exists: these replicas admit and queue, that host
    # runs the pipeline (and with it the advisor CLI its owner signed in to).
    SENTINEL_PIPELINE_WORKERS = var.brain_host.enabled ? "0" : "4"

    # SIZED TO THE TASK AND THE DATABASE. The image starts four workers when a
    # shared limiter exists; on a 0.5 vCPU task that is two too many, and with
    # each worker's pool the two tasks plus a rolling deployment exhausted a
    # db.t4g.micro's connection slots on the first real deployment. Two
    # workers x four connections x two tasks, doubled during a rollout, is 32.
    GUNICORN_WORKERS        = "2"
    SENTINEL_DB_POOL_MIN    = "1"
    SENTINEL_DB_POOL_MAX    = "4"
    SENTINEL_S3_ROOT_BUCKET = module.storage.evidence_bucket
    # Settings refuses a bucket without a region; Fargate does inject
    # AWS_REGION, but a refusal that depends on the agent's behaviour is not
    # a configuration anybody can test off-cluster.
    SENTINEL_S3_ROOT_REGION = data.aws_region.current.name

    # The publisher refuses to enumerate tenants, because each publication is
    # irreversible under COMPLIANCE retention and guessing would anchor roots
    # for estates nobody asked about.
    SENTINEL_ROOT_PUBLISH_TENANTS = join(",", var.root_publish_tenants)

    # Evidence bodies are sealed under the key injected below. Production
    # refuses to start with neither a key nor an explicit opt-out.
    SENTINEL_EVIDENCE_ENCRYPTION = "required"
    SENTINEL_ACTIVE_KEY_ID       = "K1"

    # ONE PROXY: the load balancer appends the client address to
    # X-Forwarded-For. With zero hops every client looked like the load
    # balancer, so all unauthenticated callers shared one rate-limit bucket
    # and the audit trail recorded the balancer's address for everyone.
    SENTINEL_TRUSTED_PROXY_HOPS = "1"
  }

  # INJECTED BY THE AGENT, not placed in the task definition — so they are not
  # visible to anyone holding ecs:DescribeTaskDefinition.
  secret_arns = {
    SENTINEL_DATABASE_URL  = module.database.dsn_secret_arn
    SENTINEL_REDIS_URL     = module.cache.url_secret_arn
    SENTINEL_API_KEYS      = module.secrets.secret_arns["api-keys"]
    SENTINEL_METRICS_TOKEN = module.secrets.secret_arns["metrics-token"]
    SENTINEL_DATA_KEY_K1   = module.secrets.secret_arns["evidence-data-key"]
  }

  # Optional advisor credential, injected only when an endpoint is configured.
  extra_secret_arns = merge(
    var.advisor.endpoint != "" ? {
      SENTINEL_ADVISOR_TOKEN = module.secrets.secret_arns["advisor-token"]
    } : {},
  )

  # Built from what the other modules EXPORT rather than written here. A
  # hand-written policy drifts from the resource it governs, and the drift is
  # invisible until something is denied.
  task_policy_json = [
    module.queue.consumer_policy_json,
    module.secrets.reader_policy_json,
    module.storage.publisher_policy_json,
  ]
}

module "brain_host" {
  source = "../brain_host"
  count  = var.brain_host.enabled ? 1 : 0

  name              = var.name
  subnet_id         = module.network.private_subnet_ids[0]
  security_group_id = module.ecs.task_security_group_id
  instance_type     = var.brain_host.instance_type
  advisor_model     = var.brain_host.model
  task_family       = "sentinel-${var.name}"

  secrets_reader_policy_json = module.secrets.reader_policy_json
  extra_secret_arns          = [module.database.dsn_secret_arn, module.cache.url_secret_arn]
  kms_key_arns               = [module.kms.key_arns["secrets"]]
  volume_kms_key_arn         = module.kms.key_arns["data"]
}

module "database" {
  source = "../database"

  name                = var.name
  vpc_id              = module.network.vpc_id
  database_subnet_ids = module.network.database_subnet_ids

  allowed_security_group_ids = [module.ecs.task_security_group_id]

  kms_key_arn        = module.kms.key_arns["data"]
  secret_kms_key_arn = module.kms.key_arns["secrets"]

  instance_class           = var.instance_class
  allocated_storage_gb     = var.allocated_storage_gb
  max_allocated_storage_gb = var.max_allocated_storage_gb

  multi_az              = var.multi_az
  backup_retention_days = var.backup_retention_days
  deletion_protection   = var.deletion_protection
}

module "cache" {
  source = "../cache"

  name       = var.name
  vpc_id     = module.network.vpc_id
  subnet_ids = module.network.private_subnet_ids

  allowed_security_group_ids = [module.ecs.task_security_group_id]

  kms_key_arn        = module.kms.key_arns["data"]
  secret_kms_key_arn = module.kms.key_arns["secrets"]

  node_type     = var.cache_node_type
  replica_count = var.cache_replica_count
}

module "waf" {
  source = "../waf"

  name    = var.name
  alb_arn = module.ecs.alb_arn

  blocking_enabled = var.waf_blocking

  log_retention_days = var.log_retention_days
  log_kms_key_arn    = module.kms.key_arns["logs"]
}

module "backup" {
  source = "../backup"

  name        = var.name
  kms_key_arn = module.kms.key_arns["data"]

  # The RDS instance. AWS Backup recovery points live in their own vault and
  # SURVIVE deletion of the instance, which RDS automated backups do not —
  # that is the whole reason both exist.
  resource_arns = [module.database.instance_arn]

  daily_retention_days    = var.daily_backup_retention_days
  cold_storage_after_days = 30
  monthly_retention_days  = 150

  enable_vault_lock = var.enable_vault_lock
}

module "budgets" {
  source = "../budgets"

  name              = var.name
  monthly_limit_usd = var.monthly_budget_usd

  notification_emails = var.alarm_email == "" ? [] : [var.alarm_email]
}
