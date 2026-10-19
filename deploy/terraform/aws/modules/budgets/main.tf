#############################################################################
# Sentinel — budgets and cost anomaly detection
#
# WHAT THIS COSTS: the first two budgets per account are free, then $0.02/day
# each. Cost anomaly detection is free. This is the cheapest module here and
# the one most likely to pay for itself.
#
# WHY A BUDGET IS A SECURITY CONTROL AND NOT AN ACCOUNTING ONE
# ------------------------------------------------------------
# The two most expensive AWS incidents in a small footprint are both
# security-shaped:
#
#   * a leaked credential used to mine cryptocurrency, which shows up as a
#     four-figure bill before anybody reads a CloudTrail log;
#   * a runaway loop -- an agent retrying a tool call, a worker re-reading a
#     queue -- which is exactly the failure mode an autonomous-agent platform
#     should expect in its own infrastructure.
#
# In both cases the bill moves before any functional alarm fires. Anomaly
# detection catches a shape change within a day, which is faster than a
# monthly budget and often faster than the security signal.
#
# FORECAST ALARMS FIRE BEFORE THE MONEY IS SPENT, WHICH IS THE POINT
# ------------------------------------------------------------------
# An ACTUAL threshold at 100% tells you after the fact. A FORECASTED threshold
# at 80% tells you on the 6th that this month is heading for double. Both are
# configured; the forecast one is the one that is actually useful.
#
# THE AMOUNT IS AN ESTIMATE AND SAYS SO
# -------------------------------------
# No AWS bill for this platform exists yet, so `monthly_limit_usd` is a
# ceiling somebody chose rather than a measurement. MEASURED_AWS_UNIT_ECONOMICS
# is an open external gate, and `scripts/` has no billing ingestion because
# there is nothing to ingest. Do not read the default as a projection.
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

variable "monthly_limit_usd" {
  description = <<-EOT
    Monthly ceiling in USD. AN ESTIMATE, NOT A PROJECTION.

    No bill for this platform exists yet -- MEASURED_AWS_UNIT_ECONOMICS is an
    open external gate -- so this is a number somebody chose as "more than
    this is wrong", which is what a budget is for.
  EOT
  type        = number

  validation {
    condition     = var.monthly_limit_usd > 0
    error_message = "a zero budget alarms on the first cent and gets muted, which leaves the account with no budget at all."
  }
}

variable "notification_emails" {
  description = "Where budget notifications go. Unlike SNS email, budgets need no confirmation click."
  type        = list(string)
  default     = []
}

variable "anomaly_threshold_usd" {
  description = <<-EOT
    Absolute dollar impact before an anomaly is reported.

    Not a percentage. A percentage threshold on a small account fires on noise
    -- a 200% increase on $2 is $6 -- and an operator who gets those stops
    reading them. This is the amount at which somebody should actually look.
  EOT
  type        = number
  default     = 25
}

variable "tags" {
  type    = map(string)
  default = {}
}

locals {
  tags = merge(var.tags, {
    Project   = "Sentinel"
    ManagedBy = "terraform"
    Component = "budgets"
  })

  has_recipients = length(var.notification_emails) > 0
}

resource "aws_budgets_budget" "monthly" {
  name         = "sentinel-${var.name}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_limit_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  cost_filter {
    name = "TagKeyValue"
    # Scoped to this project's tags so a shared account's other spend does not
    # drown the signal. Every module here sets Project=Sentinel, which is what
    # makes this filter work.
    values = ["user:Project$Sentinel"]
  }

  # FORECAST FIRST. This is the notification that is actually useful: it fires
  # early in the month when the trend is wrong, not at the end when the money
  # is gone.
  dynamic "notification" {
    for_each = local.has_recipients ? [1] : []
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = 80
      threshold_type             = "PERCENTAGE"
      notification_type          = "FORECASTED"
      subscriber_email_addresses = var.notification_emails
    }
  }

  # And the actual, for the case where the forecast was wrong or a single
  # large charge landed at once.
  dynamic "notification" {
    for_each = local.has_recipients ? [1] : []
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = 100
      threshold_type             = "PERCENTAGE"
      notification_type          = "ACTUAL"
      subscriber_email_addresses = var.notification_emails
    }
  }

  tags = local.tags
}

# A SECOND, MUCH SMALLER BUDGET WITH A DAILY WINDOW.
#
# The monthly budget is the wrong instrument for a leaked credential: mining
# at $50/day takes three days to breach a $150 monthly ceiling, and by then
# it is spent. A daily budget at a fraction of the monthly rate catches the
# same event on day one.
resource "aws_budgets_budget" "daily_guard" {
  name         = "sentinel-${var.name}-daily-guard"
  budget_type  = "COST"
  limit_amount = tostring(ceil(var.monthly_limit_usd / 30 * 3))
  limit_unit   = "USD"
  time_unit    = "DAILY"

  dynamic "notification" {
    for_each = local.has_recipients ? [1] : []
    content {
      comparison_operator        = "GREATER_THAN"
      threshold                  = 100
      threshold_type             = "PERCENTAGE"
      notification_type          = "ACTUAL"
      subscriber_email_addresses = var.notification_emails
    }
  }

  tags = local.tags
}

resource "aws_ce_anomaly_monitor" "this" {
  name              = "sentinel-${var.name}"
  monitor_type      = "DIMENSIONAL"
  monitor_dimension = "SERVICE"
}

resource "aws_ce_anomaly_subscription" "this" {
  count = local.has_recipients ? 1 : 0

  name      = "sentinel-${var.name}"
  frequency = "DAILY"

  monitor_arn_list = [aws_ce_anomaly_monitor.this.arn]

  dynamic "subscriber" {
    for_each = var.notification_emails
    content {
      type    = "EMAIL"
      address = subscriber.value
    }
  }

  # An ABSOLUTE dollar threshold, not a percentage. A percentage on a small
  # account fires on noise and trains people to ignore it.
  threshold_expression {
    dimension {
      key           = "ANOMALY_TOTAL_IMPACT_ABSOLUTE"
      match_options = ["GREATER_THAN_OR_EQUAL"]
      values        = [tostring(var.anomaly_threshold_usd)]
    }
  }
}

output "monthly_limit_usd" {
  value = var.monthly_limit_usd
}

output "daily_guard_usd" {
  description = "The daily ceiling that catches a leaked credential on day one rather than day three."
  value       = ceil(var.monthly_limit_usd / 30 * 3)
}

output "notifications_configured" {
  description = "False means the budgets exist and notify nobody, which is a budget in name only."
  value       = local.has_recipients
}

output "limit_is_measured" {
  description = <<-EOT
    Always FALSE. A constant, on purpose.

    MEASURED_AWS_UNIT_ECONOMICS is an open external gate: no bill for this
    platform exists, so the limit is a chosen ceiling and not a projection.
    Hardcoded so no report can present it as a cost model.
  EOT
  value       = false
}
