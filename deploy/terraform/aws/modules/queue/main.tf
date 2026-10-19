#############################################################################
# Sentinel — queue
#
# WHAT THIS COSTS: the first million requests each month are free, then $0.40
# per million. A control plane processing 100k events/day is ~$1.20/month.
# Long polling is what keeps it there — see below.
#
# LONG POLLING IS NOT AN OPTIMISATION, IT IS THE COST MODEL
# ---------------------------------------------------------
# SQS bills per REQUEST, and an empty receive is a request. A worker polling
# with `wait_time_seconds = 0` in a tight loop issues millions of empty
# receives a day and turns a $1/month queue into a $50/month one while
# delivering nothing. `receive_wait_time_seconds = 20` — the maximum — means an
# idle worker issues three requests a minute instead of thousands.
#
# EVERY QUEUE HAS A DEAD-LETTER QUEUE, AND THE DLQ HAS AN ALARM
# --------------------------------------------------------------
# A redrive policy without an alarm is a place messages go to be forgotten.
# The alarm is in the observability module; the queue exports its ARN so the
# two cannot drift apart.
#
# `maxReceiveCount` is 5. Higher means a genuinely poisonous message is
# retried for hours and burns the same handler repeatedly; lower means a
# transient database blip discards work that would have succeeded.
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
  description = "CMK for at-rest encryption of queued messages."
  type        = string
}

variable "visibility_timeout_seconds" {
  description = <<-EOT
    How long a received message is hidden from other workers.

    Must exceed the longest handler run time. Set too low, a slow handler's
    message becomes visible again and a SECOND worker starts the same work —
    which for a containment action means performing it twice.
  EOT
  type        = number
  default     = 300
}

variable "message_retention_seconds" {
  description = "How long an unprocessed message survives. 14 days is the maximum."
  type        = number
  default     = 1209600
}

variable "max_receive_count" {
  description = "Deliveries before a message goes to the DLQ."
  type        = number
  default     = 5

  validation {
    condition     = var.max_receive_count >= 2 && var.max_receive_count <= 10
    error_message = "max_receive_count must be 2-10. One means a single transient failure discards the work; above ten a poisonous message burns the same handler for hours."
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
    Component = "queue"
  })

  queues = {
    ingest      = "Inbound agent events awaiting admission and policy evaluation."
    outbox      = "SIEM export and webhook delivery intents. Retried with the lease and attempt machinery in sentinel/infrastructure/sql."
    remediation = "Approved containment and remediation actions. Visibility timeout matters most here: a duplicate delivery means performing a destructive action twice."
  }
}

resource "aws_sqs_queue" "dlq" {
  for_each = local.queues

  name = "sentinel-${var.name}-${each.key}-dlq"

  # The DLQ keeps messages for the maximum. A dead letter that expires before
  # anybody looks at it is a silently discarded failure.
  message_retention_seconds = 1209600

  kms_master_key_id                 = var.kms_key_arn
  kms_data_key_reuse_period_seconds = 300

  tags = merge(local.tags, {
    Name  = "${var.name}-${each.key}-dlq"
    Queue = each.key
    Role  = "dead-letter"
  })
}

resource "aws_sqs_queue" "this" {
  for_each = local.queues

  name = "sentinel-${var.name}-${each.key}"

  visibility_timeout_seconds = var.visibility_timeout_seconds
  message_retention_seconds  = var.message_retention_seconds

  # THE COST DECISION. 20 is the maximum and the only sensible value: SQS bills
  # per request and an empty receive is a request.
  receive_wait_time_seconds = 20

  kms_master_key_id = var.kms_key_arn
  # Reuse the data key for five minutes to cut KMS request charges. Longer
  # windows keep the key material in memory longer for marginal savings.
  kms_data_key_reuse_period_seconds = 300

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq[each.key].arn
    maxReceiveCount     = var.max_receive_count
  })

  tags = merge(local.tags, {
    Name  = "${var.name}-${each.key}"
    Queue = each.key
  })
}

# HTTPS-only, on every queue including the DLQs. A queue reachable over plain
# HTTP is a queue whose messages can be read in transit, and agent events
# carry the parameters of the actions being authorized.
resource "aws_sqs_queue_policy" "tls_only" {
  for_each = merge(
    { for key, queue in aws_sqs_queue.this : key => queue.id },
    { for key, queue in aws_sqs_queue.dlq : "${key}-dlq" => queue.id },
  )

  queue_url = each.value

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyUnencryptedTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "sqs:*"
      Resource  = "*"
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

output "queue_urls" {
  value = { for key, queue in aws_sqs_queue.this : key => queue.url }
}

output "queue_arns" {
  value = { for key, queue in aws_sqs_queue.this : key => queue.arn }
}

output "dlq_arns" {
  description = "Exported so the observability module can alarm on them. A redrive policy without an alarm is a place messages go to be forgotten."
  value       = { for key, queue in aws_sqs_queue.dlq : key => queue.arn }
}

output "dlq_names" {
  value = { for key, queue in aws_sqs_queue.dlq : key => queue.name }
}

output "consumer_policy_json" {
  description = "Least privilege for a worker: receive, delete, change visibility. No sqs:* and no purge."
  value = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:ChangeMessageVisibility",
          "sqs:GetQueueAttributes",
          "sqs:GetQueueUrl",
          "sqs:SendMessage",
        ]
        Resource = concat(
          [for queue in aws_sqs_queue.this : queue.arn],
          # SendMessage to the DLQ is not granted; SQS moves messages itself.
          # Receiving from a DLQ is an operator action, not an app one.
          [],
        )
      },
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = var.kms_key_arn
        Condition = {
          StringEquals = { "kms:ViaService" = "sqs.*.amazonaws.com" }
        }
      },
    ]
  })
}
