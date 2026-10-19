#############################################################################
# Sentinel — secrets
#
# WHAT THIS COSTS: $0.40/month per secret plus $0.05 per 10,000 API calls.
# Five secrets is $2.00/month. The API charge matters only if something reads
# a secret per request instead of caching it at startup, which is a bug rather
# than a cost decision.
#
# WHAT THIS MODULE DELIBERATELY DOES NOT DO: SET A SECRET VALUE.
# --------------------------------------------------------------
# It creates the containers and leaves them EMPTY. A value passed to Terraform
# is a value in Terraform state, and state is a file that gets copied to
# laptops, committed by accident, and read by everyone with access to the
# bucket. `.gitignore` in this repository excludes terraform state for exactly
# that reason, which is an admission that state is dangerous rather than a
# solution to it.
#
# So the values are written out of band — by the RDS module for the database
# credential it generates, or by an operator through the CLI. `terraform plan`
# on a second run shows no drift, because this module does not manage the
# value it does not set.
#
# `ignore_changes` on the version is what makes that true rather than
# aspirational: without it, Terraform would notice the operator's value and
# offer to replace it with an empty string on the next apply.
#############################################################################

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "name" {
  type = string
}

variable "kms_key_arn" {
  description = "CMK for these secrets. Separate from the data key."
  type        = string
}

variable "recovery_window_days" {
  description = <<-EOT
    Days a deleted secret can be restored.

    30 is the maximum and the default. Zero means immediate irreversible
    deletion, which AWS permits and which turns a fat-fingered `delete-secret`
    into an outage nobody can undo.
  EOT
  type        = number
  default     = 30

  validation {
    condition     = var.recovery_window_days >= 7
    error_message = "recovery_window_days below 7 makes a mistyped deletion unrecoverable. Prefer 30."
  }
}

variable "extra_secrets" {
  description = "Additional secrets for this environment only: logical name -> what reads it. Same key, same reader policy, same no-value rule."
  type        = map(string)
  default     = {}
}

variable "tags" {
  type    = map(string)
  default = {}
}

locals {
  tags = merge(var.tags, {
    Project   = "Sentinel"
    ManagedBy = "terraform"
    Component = "secrets"
  })

  # Each entry names WHAT reads it, so an operator finding an empty secret
  # knows which component is about to fail and why.
  fixed_secrets = {
    api-keys = {
      description = "SENTINEL_API_KEYS: tenant:key:role entries. Read once at startup by Settings.from_environment; production refuses to start without at least one, and refuses keys shorter than 32 characters."
    }
    siem-token = {
      description = "SENTINEL_SIEM_WEBHOOK_TOKEN: bearer token for the SIEM collector. Empty means no export intent is enqueued at all, which is a supported state rather than exports being dropped."
    }
    metrics-token = {
      description = "SENTINEL_METRICS_TOKEN: required for the /metrics/prometheus scrape. Without it the endpoint is unauthenticated, which is why it is required rather than optional."
    }
    evidence-data-key = {
      description = "SENTINEL_DATA_KEY_K1: base64 of 32 random bytes. Seals every evidence body; production refuses to start without a data key or an explicit SENTINEL_EVIDENCE_ENCRYPTION=off. BACK IT UP: losing it loses every evidence body sealed under it."
    }
    attestation-token = {
      description = "SENTINEL_ATTESTATION_TOKEN: bearer token for the external attestation endpoint. HTTPS only; a redirect that forwarded this token was a proven leak in this codebase, which is why the outbound client refuses redirects."
    }
  }

  secrets = merge(local.fixed_secrets, { for name, reader in var.extra_secrets : name => { description = reader } })
}

resource "aws_secretsmanager_secret" "this" {
  for_each = local.secrets

  name        = "sentinel/${var.name}/${each.key}"
  description = each.value.description
  kms_key_id  = var.kms_key_arn

  recovery_window_in_days = var.recovery_window_days

  tags = merge(local.tags, { Name = "${var.name}-${each.key}" })
}

# THE CONTAINER, NOT THE VALUE.
#
# An empty placeholder so the secret exists and can be read by an IAM policy
# before anybody has filled it in, with `ignore_changes` so the operator's real
# value is never offered up for replacement on a later apply. Terraform manages
# the existence of this secret and explicitly not its contents.
resource "aws_secretsmanager_secret_version" "placeholder" {
  for_each = local.secrets

  secret_id     = aws_secretsmanager_secret.this[each.key].id
  secret_string = jsonencode({ placeholder = "set out of band; see module header" })

  lifecycle {
    ignore_changes = [secret_string, version_stages]
  }
}

output "secret_arns" {
  description = "logical name -> ARN. Values are NOT managed here."
  value       = { for key, resource in aws_secretsmanager_secret.this : key => resource.arn }
}

output "reader_policy_json" {
  description = <<-EOT
    Least-privilege read policy for the task role.

    GetSecretValue and DescribeSecret only, scoped to this deployment's prefix.
    No PutSecretValue: an application that can rewrite its own credentials can
    lock its operators out of it, and nothing in Sentinel needs to.
  EOT
  value = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
        Resource = [for resource in aws_secretsmanager_secret.this : resource.arn]
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = var.kms_key_arn
        Condition = {
          StringEquals = { "kms:ViaService" = "secretsmanager.*.amazonaws.com" }
        }
      },
    ]
  })
}

output "how_to_set_a_value" {
  description = "Printed so the out-of-band step is not folklore."
  value = join("\n", [
    for key, resource in aws_secretsmanager_secret.this :
    "aws secretsmanager put-secret-value --secret-id ${resource.name} --secret-string '<value>'"
  ])
}
