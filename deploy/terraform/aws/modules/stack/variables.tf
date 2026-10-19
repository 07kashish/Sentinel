#############################################################################
# Sentinel — stack inputs
#
# Every value the three environments differ on, and nothing else. The wiring
# between the twelve modules lives in main.tf and is identical everywhere,
# which is the point: copied three times, those wires drift — a security group
# that stops being passed to the database in one environment and nobody
# notices, because each root looks internally consistent on its own.
#
# The defaults here are the DEV defaults, i.e. the cheapest and weakest. Each
# stronger environment states what it strengthens, so a posture is a readable
# list rather than something you reconstruct by diffing three files.
#############################################################################

variable "name" {
  description = "Environment name: dev, pilot, production. Prefixes every resource."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,15}$", var.name))
    error_message = "name must be lowercase alphanumeric with hyphens, 2-16 characters. It prefixes S3 bucket names, which have stricter rules than most AWS resources."
  }
}

variable "sentinel_env" {
  description = <<-EOT
    SENTINEL_ENV for the application.

    "production" makes the preflight requirements mandatory: explicit CORS
    origins, API keys of at least 32 characters, PostgreSQL rather than
    SQLite, and an explicit answer on rate-limit fail-open and execution
    binding. A pilot environment that sets this to "development" is a pilot
    that is not testing what production will do.
  EOT
  type        = string
  default     = "development"

  validation {
    condition     = contains(["development", "staging", "production"], var.sentinel_env)
    error_message = "sentinel_env must be development, staging or production; Settings.from_environment refuses anything else."
  }
}

variable "cidr_block" {
  type    = string
  default = "10.42.0.0/16"
}

variable "availability_zones" {
  type = list(string)
}

variable "image" {
  description = "Pinned by DIGEST. The ecs module refuses a tag, because a tag can be repointed after review."
  type        = string
}

# ── network ───────────────────────────────────────────────────────────────

variable "enable_nat_gateway" {
  description = "~$32/month per AZ before any traffic. False means tasks cannot reach the public internet."
  type        = bool
  default     = false
}

variable "single_nat_gateway" {
  description = "One NAT instead of one per AZ. Cheaper, and a single point of failure whose blast radius is all private egress."
  type        = bool
  default     = true
}

variable "interface_endpoints" {
  description = "~$7.20/month each per AZ. Empty means tasks cannot reach ECR or Secrets Manager unless NAT is on."
  type        = list(string)
  default     = []
}

variable "flow_log_retention_days" {
  type    = number
  default = 7
}

# ── database ──────────────────────────────────────────────────────────────

variable "instance_class" {
  type    = string
  default = "db.t4g.micro"
}

variable "allocated_storage_gb" {
  type    = number
  default = 20
}

variable "max_allocated_storage_gb" {
  description = "Autoscaling ceiling. A runaway ingest loop should hit a wall, not present a bill."
  type        = number
  default     = 40
}

variable "multi_az" {
  description = "Roughly doubles the instance cost and is what makes an AZ loss survivable."
  type        = bool
  default     = false
}

variable "backup_retention_days" {
  description = "Also the PITR window the DR drills measure against."
  type        = number
  default     = 7
}

variable "deletion_protection" {
  type    = bool
  default = false
}

# ── cache ─────────────────────────────────────────────────────────────────

variable "cache_node_type" {
  type    = string
  default = "cache.t4g.micro"
}

variable "cache_replica_count" {
  description = "Zero means losing the node re-opens every authorization nonce spent since the last snapshot."
  type        = number
  default     = 0
}

# ── compute ───────────────────────────────────────────────────────────────

variable "task_cpu" {
  type    = number
  default = 512
}

variable "task_memory" {
  type    = number
  default = 1024
}

variable "desired_count" {
  type    = number
  default = 1
}

variable "min_capacity" {
  type    = number
  default = 1
}

variable "max_capacity" {
  type    = number
  default = 2
}

variable "certificate_arn" {
  description = "Empty means the listener serves plain HTTP, reported in `posture`."
  type        = string
  default     = ""
}

variable "mcp_proxy" {
  description = "Opt-in pilot routing. Enroll and review each upstream before enabling; hosts must be explicit."
  type = object({
    enabled       = bool
    allowed_hosts = set(string)
  })
  default = { enabled = false, allowed_hosts = [] }
  validation {
    condition = !var.mcp_proxy.enabled || (
      length(var.mcp_proxy.allowed_hosts) > 0 &&
      alltrue([for host in var.mcp_proxy.allowed_hosts : can(regex("^[a-zA-Z0-9][a-zA-Z0-9.-]*$", host))])
    )
    error_message = "Enable MCP routing only with explicit upstream host names (no URLs or wildcards)."
  }
}

variable "advisor" {
  description = <<-EOT
    The advisory model: an OpenAI-compatible chat-completions base URL and a
    model name. ADVISORY ONLY by architecture -- its text lands in advisory_*
    facts and the incident report; priority stays a deterministic function of
    severity. The token is never here: when an endpoint is set the stack
    creates the `advisor-token` secret, the OWNER puts the provider key in it
    BEFORE the service rolls, and the service refuses to start if the three
    are not all present. Empty endpoint = no advisor, stated as such.
  EOT
  type = object({
    endpoint = string
    model    = string
  })
  default = { endpoint = "", model = "" }
  validation {
    condition = var.advisor.endpoint == "" || (
      can(regex("^https://[A-Za-z0-9.-]+(/[A-Za-z0-9._~/-]*)?$", var.advisor.endpoint)) && var.advisor.model != ""
    )
    error_message = "advisor.endpoint must be an https URL without query or userinfo, and advisor.model must be named with it."
  }
}

# ── application posture ───────────────────────────────────────────────────

variable "cors_origins" {
  description = "Explicit browser origins. Production refuses a wildcard on a credentialed API."
  type        = string
}

variable "require_execution_binding" {
  description = <<-EOT
    Refuse the unbound tool path, so every side effect carries an
    ExecutionAuthorization.

    False leaves `ProtectedToolRunner.execute` usable, and that path binds
    nothing. See docs/EXECUTION_TRUST_ARCHITECTURE.md for what is and is not
    closed even when this is true.
  EOT
  type        = bool
  default     = false
}

variable "rate_limit_fail_open" {
  description = "When the limiter is unreachable: allow (losing the limit) or deny (losing availability)."
  type        = bool
  default     = false
}

variable "waf_blocking" {
  description = "False puts every WAF rule in COUNT mode, so nothing is blocked."
  type        = bool
  default     = false
}

# ── retention ─────────────────────────────────────────────────────────────

variable "evidence_retention_days" {
  description = "IRREVERSIBLE. Object Lock COMPLIANCE retention cannot be shortened, by anyone."
  type        = number
  default     = 365
}

variable "artifact_retention_days" {
  type    = number
  default = 30
}

variable "log_retention_days" {
  type    = number
  default = 14
}

variable "daily_backup_retention_days" {
  type    = number
  default = 7
}

variable "enable_vault_lock" {
  description = "IRREVERSIBLE once the grace window passes. What makes a backup survive an attacker with admin credentials."
  type        = bool
  default     = false
}

# ── operations ────────────────────────────────────────────────────────────

variable "alarm_email" {
  description = "Empty means alarms fire into a topic nobody is subscribed to, reported in `posture`."
  type        = string
  default     = ""
}

variable "monthly_budget_usd" {
  type = number
}

variable "estimated_monthly_usd" {
  description = "ESTIMATED, not measured. MEASURED_AWS_UNIT_ECONOMICS is an open external gate."
  type        = number
}

variable "brain_host" {
  description = <<-EOT
    One small instance that runs the service image as the pipeline replica, on
    a host where the owner installs and signs in to their advisor CLI. While it
    is enabled the Fargate replicas run ZERO pipeline threads, so incidents
    wait in the queue until this host is up. The advisor stays advisory.
  EOT
  type = object({
    enabled       = bool
    instance_type = string
    model         = string
  })
  default = { enabled = false, instance_type = "t4g.small", model = "" }
  validation {
    condition     = !var.brain_host.enabled || can(regex("^[A-Za-z0-9][A-Za-z0-9._-]*$", var.brain_host.model))
    error_message = "brain_host.model must be a single model name when the brain host is enabled."
  }
}

variable "root_publish_tenants" {
  description = <<-EOT
    Tenants whose transparency-log root is published daily to the object-locked
    evidence bucket. A published root is what makes a tenant's proofs
    independently verifiable: a verifier compares the log against a copy the
    operator can no longer alter. Each publication is irreversible under
    COMPLIANCE retention, so tenants are named, never enumerated.
  EOT
  type    = list(string)
  default = []
  validation {
    condition     = alltrue([for t in var.root_publish_tenants : can(regex("^[a-z0-9][a-z0-9-]{0,62}$", t))])
    error_message = "tenant ids: lowercase letters, digits and hyphens."
  }
}

variable "console_demo_enabled" {
  description = <<-EOT
    Publish a VIEWER key on the console's sign-in page so its link can be
    shared with people who hold no credential. Anyone with the link holds
    that key; the service refuses to start if it names any other role.
    False everywhere except an environment built for demonstration.
  EOT
  type        = bool
  default     = false
}
