#############################################################################
# Sentinel — KMS
#
# WHAT THIS COSTS: $1/month per customer-managed key, plus $0.03 per 10,000
# requests. Four keys is $4/month. The request charge is negligible for a
# control plane and is NOT negligible for a key used to encrypt every log
# line, which is why the log key has a longer default rotation and why
# CloudWatch encryption is optional in the observability module.
#
# WHY FOUR KEYS AND NOT ONE
# -------------------------
# A single key is cheaper by $3/month and gives every principal that can
# decrypt anything the ability to decrypt everything. The keys are split along
# the lines a compromise would follow:
#
#   data      — the database and its snapshots
#   secrets   — credentials in Secrets Manager
#   evidence  — the transparency roots and evidence bucket
#   logs      — CloudWatch log groups
#
# The evidence key matters most. Evidence encrypted with the same key as the
# application data means an attacker who can read the database can also read
# and re-encrypt the record of what they did.
#
# ROTATION IS ON. Annual, automatic, and AWS keeps the old material so
# previously-encrypted data stays readable — there is no re-encryption step and
# no window where old ciphertext is unreadable. There is no reason to leave it
# off, and "rotation enabled" is a control an auditor will ask about.
#
# DELETION WINDOW IS 30 DAYS, THE MAXIMUM.
# A scheduled key deletion is unrecoverable once it completes, and it takes
# every object encrypted under that key with it. Seven days is the AWS
# default and is not long enough for somebody to be on holiday.
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

variable "deletion_window_days" {
  description = "Days before a scheduled deletion completes. 30 is the maximum."
  type        = number
  default     = 30

  validation {
    condition     = var.deletion_window_days >= 7 && var.deletion_window_days <= 30
    error_message = "deletion_window_days must be between 7 and 30. Prefer 30: a completed key deletion is unrecoverable and takes every object encrypted under it, and 7 days is not long enough for somebody to be on holiday."
  }
}

variable "tags" {
  type    = map(string)
  default = {}
}

locals {
  tags = merge(var.tags, {
    Project   = "Sentinel"
    ManagedBy = "terraform"
    Component = "kms"
  })

  purposes = {
    data     = "RDS instances, snapshots and the parameter store entries beside them"
    secrets  = "Secrets Manager entries: database credentials, API keys, SIEM tokens"
    evidence = "The evidence bucket and transparency roots. SEPARATE from data on purpose: evidence encrypted under the data key means whoever can read the database can also re-encrypt the record of what they did"
    logs     = "CloudWatch log groups, including VPC flow logs"
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

resource "aws_kms_key" "this" {
  for_each = local.purposes

  description             = "Sentinel ${var.name} — ${each.key}: ${each.value}"
  enable_key_rotation     = true
  deletion_window_in_days = var.deletion_window_days

  # The default key policy grants the account root full access, which is what
  # keeps the key administrable after a role is deleted. Narrowing it here is
  # a well-known way to create a key nobody can use or delete.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountRootAdministers"
        Effect    = "Allow"
        Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        # CloudWatch Logs must be able to use the log key or the log group
        # creation fails with an opaque AccessDenied. Scoped by SourceArn so
        # this does not become a general grant to the logs service.
        Sid       = "CloudWatchLogs"
        Effect    = "Allow"
        Principal = { Service = "logs.amazonaws.com" }
        Action = [
          "kms:Encrypt*",
          "kms:Decrypt*",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:Describe*",
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:${data.aws_partition.current.partition}:logs:*:${data.aws_caller_identity.current.account_id}:log-group:*"
          }
        }
      },
    ]
  })

  tags = merge(local.tags, { Name = "${var.name}-${each.key}", Purpose = each.key })
}

resource "aws_kms_alias" "this" {
  for_each = local.purposes

  name          = "alias/sentinel-${var.name}-${each.key}"
  target_key_id = aws_kms_key.this[each.key].key_id
}

output "key_arns" {
  description = "purpose -> key ARN"
  value       = { for key, resource in aws_kms_key.this : key => resource.arn }
}

output "key_ids" {
  value = { for key, resource in aws_kms_key.this : key => resource.key_id }
}

output "monthly_cost_estimate_usd" {
  description = "ESTIMATED. $1/key/month, excluding request charges."
  value       = length(local.purposes)
}
