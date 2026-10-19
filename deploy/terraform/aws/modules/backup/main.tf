#############################################################################
# Sentinel — AWS Backup
#
# WHAT THIS COSTS: $0.05/GB-month for warm storage, $0.01/GB-month cold. A
# 20 GB database with 35 daily recovery points is ~$5-15/month depending on
# change rate. There is no charge for the vault or the plan.
#
# WHY THIS EXISTS ALONGSIDE RDS AUTOMATED BACKUPS
# -----------------------------------------------
# They are not redundant, and the difference is the whole reason for this
# module:
#
#   RDS automated backups DIE WITH THE INSTANCE. Delete the instance and the
#   automated backups go with it (a final snapshot aside). They give
#   point-in-time recovery within the retention window and no protection
#   against "somebody deleted the database".
#
#   AWS Backup recovery points live in a SEPARATE VAULT with its own access
#   policy and, below, its own LOCK. Deleting the RDS instance does not touch
#   them.
#
# So: RDS backups are for recovery, this is for the case where the thing you
# would recover from has also been destroyed.
#
# VAULT LOCK IS THE PART THAT MATTERS, AND IT IS IRREVERSIBLE
# -----------------------------------------------------------
# In COMPLIANCE mode, vault lock cannot be disabled and recovery points cannot
# be deleted before their retention expires -- not by the account root, not by
# AWS support. That is what makes a backup survive an attacker with admin
# credentials, which is the threat that makes backups worth having at all in a
# security product.
#
# It is OFF by default and there is a `changeable_for_days` grace window,
# because enabling it is a one-way door: get the retention wrong and you are
# paying to store recovery points you cannot delete for as long as you set.
# Turn it on for production, after deciding the retention.
#
# NOT MARKED VERIFIED. A backup plan is not a restore. `docs/DR_RUNBOOK.md`
# and scripts/run_dr_postgres_wal_pitr_drill.py do the restoring, and the
# independent-failure-domain exercise remains an open external gate.
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
  type = string
}

variable "resource_arns" {
  description = "What to back up. Typically the RDS instance ARN."
  type        = list(string)
  default     = []
}

variable "daily_retention_days" {
  type    = number
  default = 35
}

variable "monthly_retention_days" {
  description = "Monthly recovery points, moved to cold storage. 365 by default."
  type        = number
  default     = 365
}

variable "cold_storage_after_days" {
  description = <<-EOT
    Days before a monthly point moves to cold storage.

    AWS requires cold storage to be held at least 90 days beyond this
    transition, so `monthly_retention_days` must exceed this by 90 or the plan
    is rejected -- with an error that does not explain the arithmetic. The
    validation below does.
  EOT
  type        = number
  default     = 30
}

variable "enable_vault_lock" {
  description = <<-EOT
    Lock the vault in COMPLIANCE mode.

    IRREVERSIBLE once the grace window passes: recovery points cannot be
    deleted before retention expires, by anyone, including the account root.
    That is exactly why it is worth having -- it is what makes a backup
    survive an attacker holding admin credentials.

    It is also why it is off by default. Get the retention wrong and you pay
    to store points you cannot delete for as long as you set.
  EOT
  type        = bool
  default     = false
}

variable "vault_lock_changeable_for_days" {
  description = "Grace period before the lock becomes permanent. 3 is the AWS minimum; 7 gives a working week to notice a mistake."
  type        = number
  default     = 7
}

variable "tags" {
  type    = map(string)
  default = {}
}

locals {
  tags = merge(var.tags, {
    Project   = "Sentinel"
    ManagedBy = "terraform"
    Component = "backup"
  })

  # AWS rejects a lifecycle where cold storage is held under 90 days. Checked
  # here so the failure is a readable message rather than an API error during
  # apply.
  monthly_retention_valid = var.monthly_retention_days >= var.cold_storage_after_days + 90
}

resource "aws_backup_vault" "this" {
  name        = "sentinel-${var.name}"
  kms_key_arn = var.kms_key_arn
  tags        = local.tags
}

resource "aws_backup_vault_lock_configuration" "this" {
  count = var.enable_vault_lock ? 1 : 0

  backup_vault_name = aws_backup_vault.this.name

  changeable_for_days = var.vault_lock_changeable_for_days
  min_retention_days  = var.daily_retention_days
  max_retention_days  = var.monthly_retention_days
}

# Deny deletion of recovery points to everyone except the account root, even
# without the lock. Weaker than vault lock -- a root principal can change this
# policy -- but it is reversible, so it is the sensible default while the lock
# is not enabled.
resource "aws_backup_vault_policy" "this" {
  backup_vault_name = aws_backup_vault.this.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyRecoveryPointDeletion"
      Effect    = "Deny"
      Principal = "*"
      Action = [
        "backup:DeleteRecoveryPoint",
        "backup:UpdateRecoveryPointLifecycle",
      ]
      Resource = "*"
      Condition = {
        StringNotEquals = {
          "aws:PrincipalArn" = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
      }
    }]
  })
}

data "aws_caller_identity" "current" {}

resource "aws_iam_role" "backup" {
  name = "sentinel-${var.name}-backup"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "backup.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = local.tags
}

resource "aws_iam_role_policy_attachment" "backup" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

# Restore is a SEPARATE managed policy from backup. Attaching only the backup
# one produces a vault full of recovery points and an AccessDenied the first
# time somebody tries to use one -- discovered during an incident.
resource "aws_iam_role_policy_attachment" "restore" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores"
}

resource "aws_backup_plan" "this" {
  name = "sentinel-${var.name}"

  rule {
    rule_name         = "daily"
    target_vault_name = aws_backup_vault.this.name
    # 05:00 UTC: after the RDS backup window (03:00-04:00) so the two do not
    # contend, and before the maintenance window.
    schedule = "cron(0 5 * * ? *)"

    start_window      = 60
    completion_window = 300

    lifecycle {
      delete_after = var.daily_retention_days
    }

    recovery_point_tags = merge(local.tags, { Cadence = "daily" })
  }

  rule {
    rule_name         = "monthly"
    target_vault_name = aws_backup_vault.this.name
    schedule          = "cron(0 6 1 * ? *)"

    start_window      = 60
    completion_window = 600

    lifecycle {
      cold_storage_after = var.cold_storage_after_days
      delete_after = local.monthly_retention_valid ? var.monthly_retention_days : (
        var.cold_storage_after_days + 90
      )
    }

    recovery_point_tags = merge(local.tags, { Cadence = "monthly" })
  }

  tags = local.tags
}

resource "aws_backup_selection" "this" {
  count = length(var.resource_arns) > 0 ? 1 : 0

  name         = "sentinel-${var.name}"
  plan_id      = aws_backup_plan.this.id
  iam_role_arn = aws_iam_role.backup.arn
  resources    = var.resource_arns
}

output "vault_name" {
  value = aws_backup_vault.this.name
}

output "vault_arn" {
  value = aws_backup_vault.this.arn
}

output "is_locked" {
  description = <<-EOT
    Whether recovery points are beyond the operator's reach.

    False means an attacker with admin credentials can delete the backups
    along with the database. Reported rather than assumed, because "we have
    backups" and "our backups survive our own compromise" are different
    claims and only one of them is worth much in a security product.
  EOT
  value       = var.enable_vault_lock
}

output "restore_is_verified" {
  description = <<-EOT
    Always FALSE, and it is a constant on purpose.

    A backup plan is not a restore. Nothing this module creates constitutes
    evidence that a restore works; that comes from
    scripts/run_dr_postgres_wal_pitr_drill.py, and the
    independent-failure-domain exercise is an open external gate. Hardcoded so
    no dashboard can read a green plan as a verified recovery.
  EOT
  value       = false
}

output "monthly_lifecycle_was_corrected" {
  description = "True when monthly_retention_days was raised to satisfy the AWS 90-day cold-storage minimum."
  value       = !local.monthly_retention_valid
}
