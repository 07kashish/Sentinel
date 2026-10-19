#############################################################################
# Sentinel — observability
#
# WHAT THIS COSTS, and it is the line item people get wrong:
#   CloudWatch INGESTION  $0.50/GB      <- the expensive part
#   CloudWatch STORAGE    $0.03/GB-mo
#   Alarms                $0.10/alarm/month
#
# Ingestion is 16x storage, so log RETENTION is not the cost lever people
# assume it is — the bill is dominated by how much is written, not how long it
# is kept. Cutting retention from 90 days to 30 saves a rounding error;
# turning on debug logging in production triples the bill. `retention_days` is
# therefore set for what an investigation needs rather than to save money.
#
# EVERY ALARM HERE ANSWERS A QUESTION SOMEBODY WOULD ACTUALLY ASK
# ---------------------------------------------------------------
# An alarm nobody acts on trains people to ignore the channel it arrives on,
# which makes the next real alarm worse than no alarm at all. Each one below
# names what has gone wrong and what to do, in the alarm description, because
# that is the text that reaches the person at 3am.
#
# THE DEAD-LETTER ALARM IS THE MOST IMPORTANT ONE.
# A redrive policy without an alarm is a place messages go to be forgotten. A
# message in a Sentinel DLQ is an agent event that was never evaluated, or a
# containment action that was never performed.
#
# `treat_missing_data` IS SET EXPLICITLY EVERYWHERE.
# The default is `missing`, which for "no data" means "not breaching" — so an
# alarm on a metric that stops being published sits green while the thing it
# watches is dead. Each alarm below chooses, and says why.
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

variable "retention_days" {
  description = "Log retention. Sized for an investigation, not to save money -- ingestion is 16x storage."
  type        = number
  default     = 90
}

variable "kms_key_arn" {
  description = "CMK for log groups. Empty uses the AWS-managed key."
  type        = string
  default     = ""
}

variable "alarm_email" {
  description = <<-EOT
    Where alarms go. Empty creates the topic and subscribes nothing.

    An empty value is permitted because an SNS email subscription requires a
    human to click a confirmation link, which Terraform cannot do -- so the
    topic exists, the alarms fire into it, and `alarms_reach_a_human` reports
    false until somebody subscribes. Better than failing the apply, and better
    than pretending.
  EOT
  type        = string
  default     = ""
}

variable "dlq_names" {
  description = "Dead-letter queues to alarm on, from the queue module."
  type        = map(string)
  default     = {}
}

variable "ecs_cluster_name" {
  type    = string
  default = ""
}

variable "ecs_service_name" {
  type    = string
  default = ""
}

variable "db_instance_id" {
  type    = string
  default = ""
}

variable "alb_alarms" {
  description = <<-EOT
    Create the load-balancer alarms.

    A LITERAL, not derived from `alb_arn_suffix`: that value is known only
    after the load balancer exists, and `count` over an unknown value refuses
    to plan. The first real plan of this stack found exactly that.
  EOT
  type    = bool
  default = false
}

variable "alb_arn_suffix" {
  description = "The ALB's dimension value for CloudWatch, not its full ARN."
  type        = string
  default     = ""
}

variable "tags" {
  type    = map(string)
  default = {}
}

locals {
  tags = merge(var.tags, {
    Project   = "Sentinel"
    ManagedBy = "terraform"
    Component = "observability"
  })
}

resource "aws_cloudwatch_log_group" "app" {
  name              = "/sentinel/${var.name}/app"
  retention_in_days = var.retention_days
  kms_key_id        = var.kms_key_arn
  tags              = local.tags
}

resource "aws_sns_topic" "alarms" {
  name              = "sentinel-${var.name}-alarms"
  kms_master_key_id = var.kms_key_arn == "" ? "alias/aws/sns" : var.kms_key_arn
  tags              = local.tags
}

resource "aws_sns_topic_subscription" "email" {
  count = var.alarm_email == "" ? 0 : 1

  topic_arn = aws_sns_topic.alarms.arn
  protocol  = "email"
  endpoint  = var.alarm_email
}

# ── dead letters: the alarm that matters most ─────────────────────────────

resource "aws_cloudwatch_metric_alarm" "dlq" {
  for_each = var.dlq_names

  alarm_name = "sentinel-${var.name}-${each.key}-dlq"
  alarm_description = join(" ", [
    "A message reached the ${each.key} dead-letter queue, which means it",
    "failed every delivery attempt. For 'ingest' an agent event was never",
    "evaluated. For 'remediation' a containment action was never performed.",
    "Read the message, fix the cause, then redrive -- do NOT purge, because",
    "the message is the only record of what was missed.",
  ])

  namespace   = "AWS/SQS"
  metric_name = "ApproximateNumberOfMessagesVisible"
  dimensions  = { QueueName = each.value }

  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"

  # `notBreaching`. SQS publishes this metric only when a queue has been
  # active, so an idle DLQ reports nothing -- and `missing` would leave the
  # alarm in INSUFFICIENT_DATA rather than green, which reads as broken
  # monitoring and gets muted.
  treat_missing_data = "notBreaching"

  alarm_actions = [aws_sns_topic.alarms.arn]
  ok_actions    = [aws_sns_topic.alarms.arn]

  tags = local.tags
}

# ── the service is running at all ─────────────────────────────────────────

resource "aws_cloudwatch_metric_alarm" "no_running_tasks" {
  count = var.ecs_service_name == "" ? 0 : 1

  alarm_name = "sentinel-${var.name}-no-running-tasks"
  alarm_description = join(" ", [
    "The ECS service has no running tasks. Nothing is serving, and because",
    "authorization fails closed, every agent action is being refused. Check",
    "the service events for a failed image pull, a secret the execution role",
    "cannot read, or a task killed for exceeding memory.",
  ])

  namespace   = "ECS/ContainerInsights"
  metric_name = "RunningTaskCount"
  dimensions = {
    ClusterName = var.ecs_cluster_name
    ServiceName = var.ecs_service_name
  }

  statistic           = "Minimum"
  period              = 60
  evaluation_periods  = 2
  threshold           = 1
  comparison_operator = "LessThanThreshold"

  # `breaching`. If the metric stops being published, the cluster is not
  # reporting -- which is at least as bad as reporting zero. This is the one
  # alarm where absence of data must NOT read as healthy.
  treat_missing_data = "breaching"

  alarm_actions = [aws_sns_topic.alarms.arn]
  ok_actions    = [aws_sns_topic.alarms.arn]

  tags = local.tags
}

# ── the API is answering ──────────────────────────────────────────────────

resource "aws_cloudwatch_metric_alarm" "unhealthy_targets" {
  count = var.alb_alarms ? 1 : 0

  alarm_name = "sentinel-${var.name}-unhealthy-targets"
  alarm_description = join(" ", [
    "The load balancer has unhealthy targets. If this is firing alongside",
    "no-running-tasks it is the same incident; alone, it means tasks are",
    "running but failing /health/live -- most often a database migration that",
    "has not been applied, which the app refuses to serve against.",
  ])

  namespace   = "AWS/ApplicationELB"
  metric_name = "UnHealthyHostCount"
  dimensions  = { LoadBalancer = var.alb_arn_suffix }

  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 3
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.alarms.arn]

  tags = local.tags
}

resource "aws_cloudwatch_metric_alarm" "server_errors" {
  count = var.alb_alarms ? 1 : 0

  alarm_name = "sentinel-${var.name}-5xx"
  alarm_description = join(" ", [
    "The application is returning 5xx. Note that a REFUSED authorization is",
    "a 4xx by design, so this is not policy working -- it is the service",
    "failing. Check the app log group for the correlation id.",
  ])

  namespace   = "AWS/ApplicationELB"
  metric_name = "HTTPCode_Target_5XX_Count"
  dimensions  = { LoadBalancer = var.alb_arn_suffix }

  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 10
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.alarms.arn]

  tags = local.tags
}

# ── the database ──────────────────────────────────────────────────────────

resource "aws_cloudwatch_metric_alarm" "db_storage" {
  count = var.db_instance_id == "" ? 0 : 1

  alarm_name = "sentinel-${var.name}-db-storage-low"
  alarm_description = join(" ", [
    "Free database storage is below 2 GB. Storage autoscaling has a ceiling",
    "set deliberately, so this is the ceiling being approached rather than a",
    "disk that will grow on its own. A full volume makes the database",
    "read-only, which stops evidence being written.",
  ])

  namespace   = "AWS/RDS"
  metric_name = "FreeStorageSpace"
  dimensions  = { DBInstanceIdentifier = var.db_instance_id }

  statistic           = "Minimum"
  period              = 300
  evaluation_periods  = 2
  threshold           = 2147483648
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"

  alarm_actions = [aws_sns_topic.alarms.arn]

  tags = local.tags
}

resource "aws_cloudwatch_metric_alarm" "db_cpu" {
  count = var.db_instance_id == "" ? 0 : 1

  alarm_name = "sentinel-${var.name}-db-cpu"
  alarm_description = join(" ", [
    "Sustained high database CPU. On a burstable t4g class this also means",
    "CPU credits are draining, and when they run out the instance is",
    "throttled to its baseline -- which looks like the application hanging.",
  ])

  namespace   = "AWS/RDS"
  metric_name = "CPUUtilization"
  dimensions  = { DBInstanceIdentifier = var.db_instance_id }

  statistic           = "Average"
  period              = 300
  evaluation_periods  = 3
  threshold           = 80
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.alarms.arn]

  tags = local.tags
}

# ── the transparency publisher stopped ────────────────────────────────────
#
# THE QUIETEST FAILURE IN THE WHOLE SYSTEM.
#
# If the daily publisher stops, nothing breaks. The API keeps serving, proofs
# keep verifying, and `/v1/transparency/root` keeps reporting the last
# published root as independently verifiable -- truthfully, because it was.
# Nobody notices until an auditor asks why the roots stop, by which point the
# unpublished window is however long ago it broke.
#
# So the publisher emits a heartbeat metric and this alarm watches for its
# ABSENCE, with treat_missing_data = breaching. That combination is the whole
# point: the failure mode is silence.
# THE HEARTBEAT ITSELF. The alarm above was written against a metric nobody
# emitted: the service logs a structured `transparency_roots_published` event
# and never calls CloudWatch, so the alarm sat in ALARM from the day the stack
# was applied and said nothing true (found 2026-10-13, two roots published and
# the alarm still "silent"). The log is the source of truth, so the metric is
# derived from it: one datapoint per publication event that published at
# least one root. No code change, no CloudWatch credential in the task.
resource "aws_cloudwatch_log_metric_filter" "root_published" {
  name           = "sentinel-${var.name}-root-published"
  log_group_name = aws_cloudwatch_log_group.app.name
  # The report's fields are prefixed `roots_` in the log line (`roots_published`,
  # `roots_failed`, ...). The first version of this filter said `$.published`
  # and matched nothing; CloudWatch's test_metric_filter against the real line
  # is how that was caught, and is the way to check any future change.
  pattern        = "{ $.event = \"transparency_roots_published\" && $.roots_published > 0 }"

  metric_transformation {
    name          = "RootPublished"
    namespace     = "Sentinel/Transparency"
    value         = "$.roots_published"
    default_value = "0"
    unit          = "Count"
  }
}

resource "aws_cloudwatch_metric_alarm" "publisher_silent" {
  alarm_name = "sentinel-${var.name}-transparency-publisher-silent"
  alarm_description = join(" ", [
    "No transparency root has been published in over 48 hours. NOTHING ELSE",
    "WILL HAVE BROKEN -- the API serves, proofs verify, and the last root is",
    "still genuinely verifiable. What has stopped is new roots being anchored",
    "where the operator cannot rewrite them, so every event since then rests",
    "on this deployment's own word. Check the scheduled job.",
  ])

  namespace   = "Sentinel/Transparency"
  metric_name = "RootPublished"

  statistic           = "Sum"
  period              = 86400
  evaluation_periods  = 2
  threshold           = 1
  comparison_operator = "LessThanThreshold"

  # `breaching`, and this is the load-bearing setting. The failure is the
  # metric not arriving; `notBreaching` here would make the alarm permanently
  # green in exactly the case it exists to catch.
  treat_missing_data = "breaching"

  alarm_actions = [aws_sns_topic.alarms.arn]
  ok_actions    = [aws_sns_topic.alarms.arn]

  tags = local.tags
}

output "log_group_name" {
  value = aws_cloudwatch_log_group.app.name
}

output "alarm_topic_arn" {
  value = aws_sns_topic.alarms.arn
}

output "alarms_reach_a_human" {
  description = <<-EOT
    False when no email was configured.

    An SNS email subscription needs a human to click a confirmation link,
    which Terraform cannot do. Reported so a readiness check cannot count
    alarms that fire into a topic nobody is listening to.
  EOT
  value       = var.alarm_email != ""
}

output "alarm_count" {
  value = (
    length(var.dlq_names)
    + (var.ecs_service_name == "" ? 0 : 1)
    + (var.alb_arn_suffix == "" ? 0 : 2)
    + (var.db_instance_id == "" ? 0 : 2)
    + 1
  )
}
