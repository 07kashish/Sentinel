#############################################################################
# Sentinel — AWS identity layer
#
# WHAT THIS COSTS: nothing. IAM roles, policies, and OIDC identity providers
# are free. There is no NAT Gateway here, no load balancer, no database, no
# compute. Applying this module starts no billing.
#
# WHY IT IS SEPARATE FROM THE REST: because you can apply it today, safely,
# and stop needing a static access key. The infrastructure that does cost
# money lives one directory up and is plan-only until somebody decides.
#
# WHAT IT REPLACES: a long-lived `AKIA...` key pasted into a config file. That
# key has no expiry, no session, no delegation chain, and CloudTrail cannot
# tell you which workload used it. An assumed role has all four.
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

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project   = "Sentinel"
      ManagedBy = "terraform"
      Component = "identity"
    }
  }
}

variable "region" {
  type    = string
  default = "us-east-1"
}

variable "github_owner" {
  type        = string
  description = "GitHub org or user that owns the Sentinel repository"
}

variable "github_repo" {
  type        = string
  description = "Repository name, without the owner"
}

variable "release_branch" {
  type        = string
  default     = "main"
  description = <<-EOT
    The ONLY branch whose workflows may assume the release role.

    This is matched exactly, not by prefix. See the trust policy below for why
    that distinction is the whole security of this module.
  EOT
}

data "aws_caller_identity" "current" {}

#############################################################################
# GitHub Actions OIDC provider
#
# GitHub signs a short-lived token describing which repository, branch and
# workflow is running. AWS verifies it against this provider. No secret is
# stored on either side, and there is nothing to leak or rotate.
#############################################################################

resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]

  # GitHub's certificate thumbprint. AWS has verified GitHub's OIDC endpoint
  # against its own trust store since 2023 and this value is retained for
  # compatibility rather than as the security boundary.
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

#############################################################################
# Release role — the one that can push images and sign artifacts
#
# THE `sub` CONDITION IS THE ENTIRE SECURITY OF THIS ROLE.
#
# `StringEquals` on the full subject, NOT `StringLike` with a wildcard. The
# common mistake is:
#
#     "token.actions.githubusercontent.com:sub" = "repo:owner/repo:*"
#
# which matches `pull_request` events — including pull requests opened from
# FORKS. Anyone who can open a PR against the repository could then assume this
# role and push a signed image. The wildcard reads as "our repository" and
# means "anyone who can open a PR against our repository".
#
# Pinning the full `ref:refs/heads/<branch>` subject means only a workflow
# running on that branch, in that repository, can assume it.
#############################################################################

data "aws_iam_policy_document" "github_release_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values = [
        "repo:${var.github_owner}/${var.github_repo}:ref:refs/heads/${var.release_branch}"
      ]
    }
  }
}

resource "aws_iam_role" "release" {
  name                 = "SentinelRelease"
  description          = "CI release identity. Federated from GitHub OIDC; no static key exists."
  assume_role_policy   = data.aws_iam_policy_document.github_release_trust.json
  max_session_duration = 3600
}

#############################################################################
# Runtime roles — assumed by the workload, never by a person
#
# `sts:AssumeRole` is NOT granted to any of these. An agent that can assume
# another role has a privilege-escalation path, and role chaining is one of the
# things Sentinel's own blast-radius engine exists to detect. It would be a
# poor look to ship it.
#############################################################################

data "aws_iam_policy_document" "ecs_task_trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
    # Confused-deputy protection: without this, any AWS account's ECS service
    # could assume this role on their own task's behalf.
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "api" {
  name                 = "SentinelAPI"
  description          = "The authorization path. Reads config, writes evidence."
  assume_role_policy   = data.aws_iam_policy_document.ecs_task_trust.json
  max_session_duration = 3600
}

resource "aws_iam_role" "worker" {
  name                 = "SentinelWorker"
  description          = "Consumes the outbox, delivers to integrations."
  assume_role_policy   = data.aws_iam_policy_document.ecs_task_trust.json
  max_session_duration = 3600
}



#############################################################################
# Audit role — for a human, read-only, and it can read evidence
#
# An auditor reads evidence content under a dedicated read-only identity.
# Runtime and release identities remain separate from this human access path.
#############################################################################

variable "audit_principal_arns" {
  type        = list(string)
  default     = []
  description = "IAM principals that may assume the audit role. Empty means nobody."
}

data "aws_iam_policy_document" "audit_trust" {
  # An empty principal list produces a role nobody can assume, which is the
  # correct default: the role exists, and granting access is a separate,
  # deliberate act.
  count = 1

  dynamic "statement" {
    for_each = length(var.audit_principal_arns) > 0 ? [1] : []
    content {
      effect  = "Allow"
      actions = ["sts:AssumeRole"]
      principals {
        type        = "AWS"
        identifiers = var.audit_principal_arns
      }
      condition {
        test     = "Bool"
        variable = "aws:MultiFactorAuthPresent"
        values   = ["true"]
      }
    }
  }
}

resource "aws_iam_role" "audit" {
  name                 = "SentinelReadOnlyAudit"
  description          = "Human auditor. Read-only, MFA required, nobody granted by default."
  assume_role_policy   = data.aws_iam_policy_document.audit_trust[0].json
  max_session_duration = 3600
}

#############################################################################
# Outputs
#############################################################################

output "github_release_role_arn" {
  value       = aws_iam_role.release.arn
  description = "Set as the `role-to-assume` in the GitHub Actions workflow."
}


output "api_role_arn" {
  value = aws_iam_role.api.arn
}

output "worker_role_arn" {
  value = aws_iam_role.worker.arn
}

output "monthly_cost_usd" {
  value       = 0
  description = <<-EOT
    Zero. IAM roles, policies and OIDC providers are free.

    Stated as an output so it appears in `terraform plan` beside the resources,
    rather than being a claim in a document somebody has to go and find.
  EOT
}
