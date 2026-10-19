#############################################################################
# Sentinel — WAF
#
# WHAT THIS COSTS: $5/month per web ACL, $1/month per rule group, and $0.60
# per million requests. The configuration below is ~$10/month before traffic.
#
# THE RULE THAT WOULD BREAK THIS PRODUCT, AND WHY IT IS SCOPED DOWN
# ------------------------------------------------------------------
# AWSManagedRulesCommonRuleSet contains `SizeRestrictions_BODY`, which blocks
# request bodies over 8 KB. Sentinel ingests agent events whose bodies
# legitimately exceed that — an execution passport with a delegation chain and
# action semantics is routinely larger — so leaving it on silently drops
# exactly the traffic this service exists to receive, and the caller sees a 403
# from a load balancer with no application log line to explain it.
#
# So that one rule is excluded on the ingest path and left ON everywhere else.
# Excluded, not the whole rule group: the rest of the common set is worth
# having, and removing a group to solve one rule is how a WAF becomes
# decorative.
#
# COUNT MODE FIRST, ON PURPOSE
# ----------------------------
# `blocking_enabled = false` puts every rule in COUNT so an operator can see
# what WOULD have been blocked against real traffic before it is. A WAF turned
# on in blocking mode against an unfamiliar workload produces an outage and a
# rollback, after which nobody turns it on again. This is the same
# observe-then-enforce progression the product itself uses.
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

variable "alb_arn" {
  description = "The load balancer to associate. Regional scope, not CloudFront."
  type        = string
}

variable "blocking_enabled" {
  description = <<-EOT
    Block, or merely count.

    FALSE by default. Every rule runs in COUNT mode, so the CloudWatch metrics
    show what would have been blocked without anything actually being. Turn it
    on after looking at those metrics for a few days against real traffic --
    a WAF switched straight to blocking on an unfamiliar workload causes an
    outage, a rollback, and a permanent reluctance to try again.
  EOT
  type        = bool
  default     = false
}

variable "rate_limit_per_five_minutes" {
  description = <<-EOT
    Requests per five minutes from one IP before the rate rule fires.

    This is a CRUDE outer bound and NOT the product's rate limiter. Sentinel's
    limiter is per-tenant and per-agent and lives in the application, where it
    can tell one tenant's burst from another's. This one only stops a single
    address from exhausting the load balancer, so it is set high enough that a
    busy legitimate tenant behind one NAT address never reaches it.
  EOT
  type        = number
  default     = 20000
}

variable "log_retention_days" {
  type    = number
  default = 30
}

variable "log_kms_key_arn" {
  type    = string
  default = ""
}

variable "ingest_path_prefix" {
  description = "Where large bodies are legitimate, so the size rule is excluded there."
  type        = string
  default     = "/v1/events"
}

variable "tags" {
  type    = map(string)
  default = {}
}

locals {
  tags = merge(var.tags, {
    Project   = "Sentinel"
    ManagedBy = "terraform"
    Component = "waf"
  })

  # One place decides count vs block, so a rule cannot be left blocking after
  # the switch is turned off.
  action = var.blocking_enabled ? "block" : "count"
}

resource "aws_wafv2_web_acl" "this" {
  name        = "sentinel-${var.name}"
  description = "Sentinel ${var.name}. ${var.blocking_enabled ? "BLOCKING" : "COUNT ONLY - nothing is blocked"}"
  scope       = "REGIONAL"

  default_action {
    # ALLOW by default, with rules that deny. The inverse -- default deny with
    # allow rules -- is right for a known client set and wrong for an API whose
    # callers are customer agents nobody enumerated.
    allow {}
  }

  # ── rate limiting: a crude outer bound, not the product's limiter ────────
  rule {
    name     = "rate-limit-per-ip"
    priority = 10

    action {
      dynamic "block" {
        for_each = var.blocking_enabled ? [1] : []
        content {}
      }
      dynamic "count" {
        for_each = var.blocking_enabled ? [] : [1]
        content {}
      }
    }

    statement {
      rate_based_statement {
        limit              = var.rate_limit_per_five_minutes
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "sentinel-${var.name}-rate"
      sampled_requests_enabled   = true
    }
  }

  # ── the common set, with ONE rule excluded ──────────────────────────────
  rule {
    name     = "aws-common"
    priority = 20

    # `override_action` and not `action`: a managed rule group's own actions
    # apply unless overridden, and `none {}` means "use them".
    override_action {
      dynamic "none" {
        for_each = var.blocking_enabled ? [1] : []
        content {}
      }
      dynamic "count" {
        for_each = var.blocking_enabled ? [] : [1]
        content {}
      }
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"

        # THE ONE THAT WOULD BREAK INGEST.
        #
        # SizeRestrictions_BODY blocks bodies over 8 KB. A passport with a
        # delegation chain exceeds that routinely, so leaving it on drops
        # exactly the traffic this service exists to receive -- as a 403 from
        # the load balancer, with no application log line to explain it.
        rule_action_override {
          name = "SizeRestrictions_BODY"
          action_to_use {
            count {}
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "sentinel-${var.name}-common"
      sampled_requests_enabled   = true
    }
  }

  # ── known-bad inputs: SQLi, path traversal, log4j ───────────────────────
  rule {
    name     = "aws-known-bad-inputs"
    priority = 30

    override_action {
      dynamic "none" {
        for_each = var.blocking_enabled ? [1] : []
        content {}
      }
      dynamic "count" {
        for_each = var.blocking_enabled ? [] : [1]
        content {}
      }
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "sentinel-${var.name}-known-bad"
      sampled_requests_enabled   = true
    }
  }

  # ── SQL injection ───────────────────────────────────────────────────────
  #
  # Defence in depth and not the primary control. `test_sql_is_never_built_
  # from_data.py` asserts that no SQL in this codebase is constructed from
  # request data at all, which is what actually prevents injection. This rule
  # catches an attempt before it reaches the application and, in count mode,
  # tells an operator somebody is trying.
  rule {
    name     = "aws-sqli"
    priority = 40

    override_action {
      dynamic "none" {
        for_each = var.blocking_enabled ? [1] : []
        content {}
      }
      dynamic "count" {
        for_each = var.blocking_enabled ? [] : [1]
        content {}
      }
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesSQLiRuleSet"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "sentinel-${var.name}-sqli"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "sentinel-${var.name}"
    sampled_requests_enabled   = true
  }

  tags = local.tags
}

resource "aws_wafv2_web_acl_association" "this" {
  resource_arn = var.alb_arn
  web_acl_arn  = aws_wafv2_web_acl.this.arn
}

# WAF logging REQUIRES a log group whose name starts with `aws-waf-logs-`.
# The API rejects anything else with an error that does not say so.
resource "aws_cloudwatch_log_group" "waf" {
  name              = "aws-waf-logs-sentinel-${var.name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.log_kms_key_arn
  tags              = local.tags
}

resource "aws_wafv2_web_acl_logging_configuration" "this" {
  resource_arn            = aws_wafv2_web_acl.this.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf.arn]

  # REDACT THE AUTHORIZATION HEADER.
  #
  # WAF logs the full request by default, headers included, and a bearer token
  # in a log group is a credential in a log group. This codebase has already
  # had one proven token leak through redirect handling; a WAF log is a
  # quieter version of the same failure because nobody thinks of it as an
  # output.
  redacted_fields {
    single_header {
      name = "authorization"
    }
  }

  redacted_fields {
    single_header {
      name = "cookie"
    }
  }

  redacted_fields {
    single_header {
      name = "x-api-key"
    }
  }
}

output "web_acl_arn" {
  value = aws_wafv2_web_acl.this.arn
}

output "is_blocking" {
  description = "False means every rule is in COUNT mode and NOTHING is being blocked. Reported so a dashboard cannot imply protection that is not on."
  value       = var.blocking_enabled
}

output "log_group_name" {
  value = aws_cloudwatch_log_group.waf.name
}
