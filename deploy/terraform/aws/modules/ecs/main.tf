#############################################################################
# Sentinel — ECS Fargate on ARM64
#
# WHAT THIS COSTS, at the shipped defaults:
#   1 task, 0.5 vCPU / 1 GB, ARM64, always on  ~$15/month
#   ALB                                        ~$16/month + LCU charges
# The ALB is the floor: it bills hourly whether or not anything calls it, and
# it is the reason a "scale to zero" deployment still costs $16.
#
# ARM64 (Graviton), NOT x86. Roughly 20% cheaper per vCPU-hour for the same
# work. The container has to be built for it — `docker buildx --platform
# linux/arm64` — and a task definition claiming ARM64 with an x86 image fails
# to start with an exec format error that does not mention architecture, so
# `runtime_platform` is set explicitly rather than defaulted.
#
# TWO ROLES, NOT ONE, AND THE DISTINCTION IS LOAD-BEARING
# -------------------------------------------------------
#   execution role — used by the ECS AGENT before the container starts: pull
#                    the image, fetch secrets, create log streams.
#   task role      — used by the APPLICATION at runtime.
#
# Collapsing them gives the application the ability to pull any image and read
# any secret the agent could. They are separate here, and the task role is
# built from policies the other modules export rather than written by hand,
# so a least-privilege policy cannot drift from the resource it governs.
#
# FARGATE SPOT IS OFFERED FOR WORKERS AND REFUSED FOR THE API.
# Spot is ~70% cheaper and can be reclaimed with a two-minute warning. Fine
# for a queue worker whose message returns to the queue. Not fine for the
# authorization path, where a reclaimed task mid-decision is a request that
# fails closed for no reason the operator can explain.
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

variable "vpc_id" {
  type = string
}

variable "public_subnet_ids" {
  description = "For the load balancer only. Tasks never run here."
  type        = list(string)
}

variable "private_subnet_ids" {
  description = "Where tasks run. No public IP is assigned."
  type        = list(string)
}

variable "image" {
  description = "Full image reference including digest. A TAG is mutable; a digest is not."
  type        = string

  validation {
    condition     = can(regex("@sha256:[0-9a-f]{64}$", var.image))
    error_message = "image must be pinned by digest (repo@sha256:...), not by tag. A tag can be repointed after this configuration was reviewed, which makes the reviewed artifact and the deployed artifact different things."
  }
}

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
  default = 4
}

variable "environment" {
  description = "Non-secret environment variables. Secrets go through `secret_arns`."
  type        = map(string)
  default     = {}
}

variable "secret_arns" {
  description = <<-EOT
    Environment variable name -> Secrets Manager ARN.

    Injected by the ECS agent, so the value never appears in the task
    definition, in `describe-tasks`, or in the console. A secret placed in
    `environment` instead is visible to anyone with ecs:DescribeTaskDefinition.
  EOT
  type        = map(string)
  default     = {}
}

variable "extra_secret_arns" {
  description = "Optional secrets injected the same way as `secret_arns`, for settings only some environments state."
  type        = map(string)
  default     = {}
}

locals {
  injected_secret_arns = merge(var.secret_arns, var.extra_secret_arns)
}

variable "task_policy_json" {
  description = "Least-privilege policies from the other modules, as JSON documents."
  type        = list(string)
  default     = []
}

variable "log_group_name" {
  type = string
}

variable "log_kms_key_arn" {
  type    = string
  default = ""
}

variable "secret_kms_key_arn" {
  description = <<-EOT
    The CMK the injected secrets are encrypted under. The execution role
    needs kms:Decrypt on THIS key, through Secrets Manager, or every task
    dies at start with "unable to retrieve secret ... Access to KMS is not
    allowed". The first version granted decrypt on the LOG key instead --
    found on the first real deployment of this stack (2026-09-24).
  EOT
  type        = string
  default     = ""
}

variable "certificate_arn" {
  description = <<-EOT
    ACM certificate for the HTTPS listener. Empty means HTTP only.

    An empty value is permitted so a dev environment can come up before DNS
    and a certificate exist, and it is reported in `listener_is_encrypted` so
    nothing downstream assumes TLS that is not there.
  EOT
  type        = string
  default     = ""
}

variable "health_check_path" {
  description = "Must be a LIVENESS probe, not readiness: an unready task should not be killed while it waits for a migration."
  type        = string
  default     = "/health/live"
}

variable "tags" {
  type    = map(string)
  default = {}
}

locals {
  tags = merge(var.tags, {
    Project   = "Sentinel"
    ManagedBy = "terraform"
    Component = "ecs"
  })

  encrypted = var.certificate_arn != ""
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

# ── the cluster ────────────────────────────────────────────────────────────

resource "aws_ecs_cluster" "this" {
  name = "sentinel-${var.name}"

  setting {
    # Container Insights is billed per metric. On in this module because
    # "which task was killed and why" is unanswerable without it, and the
    # observability module's alarms read these metrics.
    name  = "containerInsights"
    value = "enhanced"
  }

  tags = local.tags
}

resource "aws_ecs_cluster_capacity_providers" "this" {
  cluster_name = aws_ecs_cluster.this.name

  # FARGATE only for this service. Spot is deliberately absent: a reclaimed
  # task on the authorization path is a request that fails closed for a reason
  # the operator cannot explain to the person whose action was refused.
  capacity_providers = ["FARGATE"]

  default_capacity_provider_strategy {
    capacity_provider = "FARGATE"
    weight            = 1
    base              = 1
  }
}

# ── roles ─────────────────────────────────────────────────────────────────

data "aws_iam_policy_document" "assume_task" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }

    # Confused-deputy protection. Without SourceArn, any ECS task in any
    # account could assume this role.
    #
    # The shape AWS documents for ECS task roles: every ECS resource in THIS
    # account and region, plus the account itself. The first version matched
    # `<cluster-arn>/*` and a second tried `task/<cluster-name>/*`; ECS
    # refused to assume either role under both ("ECS was unable to assume the
    # role"), so no task could start. Found on the first real deployment of
    # this stack (2026-09-24). Narrowing below the documented shape is not
    # something the service's evaluation supports, and a role no task can
    # assume protects nothing.
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values = [
        "arn:${data.aws_partition.current.partition}:ecs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*",
      ]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "sentinel-${var.name}-execution"
  description        = "Used by the ECS AGENT before the container starts: image pull, secret fetch, log stream creation. NOT by the application."
  assume_role_policy = data.aws_iam_policy_document.assume_task.json
  tags               = local.tags
}

resource "aws_iam_role_policy_attachment" "execution_managed" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# The managed policy above does NOT cover reading secrets or the CMK that
# encrypts them, which is the most common reason a task fails to start with an
# unhelpful ResourceInitializationError.
resource "aws_iam_role_policy" "execution_secrets" {
  count = length(local.injected_secret_arns) > 0 ? 1 : 0

  name = "read-injected-secrets"
  role = aws_iam_role.execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      [{
        Effect   = "Allow"
        Action   = ["secretsmanager:GetSecretValue"]
        Resource = values(local.injected_secret_arns)
      }],
      var.secret_kms_key_arn == "" ? [] : [{
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = var.secret_kms_key_arn
        Condition = {
          StringEquals = { "kms:ViaService" = "secretsmanager.${data.aws_region.current.name}.amazonaws.com" }
        }
      }],
    )
  })
}

resource "aws_iam_role" "task" {
  name               = "sentinel-${var.name}-task"
  description        = "Used by the APPLICATION at runtime. Separate from the execution role so the app cannot pull images or read secrets the agent can."
  assume_role_policy = data.aws_iam_policy_document.assume_task.json
  tags               = local.tags
}

# Built from the policies the other modules export. Writing them here by hand
# would let a least-privilege policy drift from the resource it governs.
resource "aws_iam_role_policy" "task" {
  count = length(var.task_policy_json)

  name   = "granted-${count.index}"
  role   = aws_iam_role.task.id
  policy = var.task_policy_json[count.index]
}

# ── load balancer ─────────────────────────────────────────────────────────

resource "aws_security_group" "alb" {
  name        = "sentinel-${var.name}-alb"
  description = "Public ingress to the load balancer"
  vpc_id      = var.vpc_id
  tags        = merge(local.tags, { Name = "${var.name}-alb" })
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  count = local.encrypted ? 1 : 0

  security_group_id = aws_security_group.alb.id
  description       = "HTTPS from anywhere"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "alb_http" {
  security_group_id = aws_security_group.alb.id
  # With a certificate this port only redirects; without one it serves. Both
  # cases need the rule, and the listener below decides which it is.
  description = local.encrypted ? "HTTP, redirected to HTTPS" : "HTTP (no certificate configured)"
  cidr_ipv4   = "0.0.0.0/0"
  from_port   = 80
  to_port     = 80
  ip_protocol = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "alb_to_tasks" {
  security_group_id            = aws_security_group.alb.id
  referenced_security_group_id = aws_security_group.tasks.id
  description                  = "To the application tasks only, not the internet"
  from_port                    = 8000
  to_port                      = 8000
  ip_protocol                  = "tcp"
}

resource "aws_security_group" "tasks" {
  name        = "sentinel-${var.name}-tasks"
  description = "Application tasks: ingress from the load balancer only"
  vpc_id      = var.vpc_id
  tags        = merge(local.tags, { Name = "${var.name}-tasks" })
}

resource "aws_vpc_security_group_ingress_rule" "tasks_from_alb" {
  security_group_id            = aws_security_group.tasks.id
  referenced_security_group_id = aws_security_group.alb.id
  description                  = "From the load balancer only"
  from_port                    = 8000
  to_port                      = 8000
  ip_protocol                  = "tcp"
}

# HTTPS egress, so tasks can reach VPC endpoints (and, where NAT is enabled,
# AWS APIs and any configured external endpoint). Not "all traffic": a task
# that only needs 443 should only have 443.
#
# The policy scanner (AVD-AWS-0104) wants a narrower destination than any
# address. The destinations are decided at RUNTIME by the operator -- the
# attestation gateway, the tenant SIEM sinks, the S3 root sink -- and are not
# knowable here; the application enforces them itself with a post-resolution
# address check, connection pinning and redirect refusal in
# `sentinel/infrastructure/outbound.py`. Port 443 only, TCP only, is the
# narrowest rule that does not silently break a configured integration.
#trivy:ignore:AVD-AWS-0104
resource "aws_vpc_security_group_egress_rule" "tasks_https" {
  security_group_id = aws_security_group.tasks.id
  description       = "HTTPS to VPC endpoints and AWS APIs"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

# Internet-facing BY DESIGN (AVD-AWS-0053): agents in customers' own runtimes
# reach `/v1/protect/evaluate` and `/v1/events` over the internet, which is
# the product. Exposure is bounded by the WAF in front of it, bearer
# authentication on every route but the two health probes, and the per-tenant
# throttle. An internal balancer would need every customer to peer a VPC.
#trivy:ignore:AVD-AWS-0053
resource "aws_lb" "this" {
  name               = "sentinel-${var.name}"
  load_balancer_type = "application"
  internal           = false
  subnets            = var.public_subnet_ids
  security_groups    = [aws_security_group.alb.id]

  # ON. Without it a request that returned 403 leaves no record of having been
  # made, and "was this endpoint probed" becomes unanswerable.
  drop_invalid_header_fields = true
  enable_deletion_protection = false

  # Longer than the default 60s because an evidence export or a long
  # investigation query legitimately takes over a minute, and a 504 from the
  # load balancer looks like an application bug.
  idle_timeout = 120

  tags = local.tags
}

resource "aws_lb_target_group" "this" {
  name        = "sentinel-${var.name}"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  # Shorter than the 300s default. A task that has been told to stop should
  # not hold the deployment open for five minutes.
  deregistration_delay = 30

  health_check {
    enabled  = true
    path     = var.health_check_path
    protocol = "HTTP"
    matcher  = "200"
    interval = 15
    timeout  = 5
    # Two failures to remove, three successes to add: quick to pull a broken
    # task out, deliberate about putting one back.
    healthy_threshold   = 3
    unhealthy_threshold = 2
  }

  tags = local.tags
}

# Port 80 exists to REDIRECT to 443 whenever a certificate is configured
# (AVD-AWS-0054 sees the protocol, not the action). Without a certificate it
# forwards, and `listener_is_encrypted` reports false so nothing downstream
# assumes otherwise; the production root requires a certificate, so plaintext
# forwarding is reachable only in dev.
#trivy:ignore:AVD-AWS-0054
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.this.arn
  port              = 80
  protocol          = "HTTP"

  # With a certificate: redirect and never serve on 80. Without: serve, and
  # `listener_is_encrypted` reports false so nothing assumes otherwise.
  default_action {
    type = local.encrypted ? "redirect" : "forward"

    target_group_arn = local.encrypted ? null : aws_lb_target_group.this.arn

    dynamic "redirect" {
      for_each = local.encrypted ? [1] : []
      content {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }
  }
}

resource "aws_lb_listener" "https" {
  count = local.encrypted ? 1 : 0

  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  certificate_arn   = var.certificate_arn

  # TLS 1.3 with 1.2 fallback. The AWS default policy still permits TLS 1.0.
  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
}

# ── the service ───────────────────────────────────────────────────────────

resource "aws_ecs_task_definition" "this" {
  family                   = "sentinel-${var.name}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory

  execution_role_arn = aws_iam_role.execution.arn
  task_role_arn      = aws_iam_role.task.arn

  # KEEP OLD REVISIONS. The service below ignores task-definition changes so
  # a deploy pipeline can move it; without this, a second apply deregisters
  # the revision the service still runs, and the service can no longer place
  # a task ("TaskDefinition is inactive"). Found on the first real
  # deployment of this stack (2026-09-24).
  skip_destroy = true

  runtime_platform {
    # EXPLICIT. A task definition defaulting to X86_64 with an ARM image fails
    # with an exec format error that never mentions architecture.
    cpu_architecture        = "ARM64"
    operating_system_family = "LINUX"
  }

  container_definitions = jsonencode([{
    name      = "sentinel"
    image     = var.image
    essential = true

    portMappings = [{
      containerPort = 8000
      hostPort      = 8000 # equal to containerPort on Fargate; stated so the provider stops diffing it
      protocol      = "tcp"
    }]

    # Matches the Helm chart's pod security context, so the container behaves
    # the same on both platforms rather than depending on which one runs it.
    readonlyRootFilesystem = true
    user                   = "10001:10001"

    linuxParameters = {
      # Drop every capability. A Python web service needs none of them, and
      # dropping ALL is the only list that does not need maintaining.
      capabilities       = { drop = ["ALL"], add = [] }
      initProcessEnabled = true
    }

    # Writable scratch, because the root filesystem is read-only and Python
    # needs somewhere for temporary files.
    # Empty, and STATED: AWS returns these as empty lists, and a definition
    # that omits them is replaced on every plan for a difference of nothing.
    systemControls = []
    volumesFrom    = []
    mountPoints = [{
      sourceVolume  = "tmp"
      containerPath = "/tmp"
      readOnly      = false
    }]

    environment = [
      for key, value in var.environment : { name = key, value = value }
    ]

    # Injected by the AGENT. Never in the task definition, so not visible to
    # anyone holding ecs:DescribeTaskDefinition.
    secrets = [
      for key, arn in local.injected_secret_arns : { name = key, valueFrom = arn }
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = var.log_group_name
        "awslogs-region"        = data.aws_region.current.name
        "awslogs-stream-prefix" = "sentinel"
      }
    }

    # A container-level health check as well as the target group's. The target
    # group decides whether to route; this decides whether to restart, and
    # they are different questions.
    healthCheck = {
      command     = ["CMD-SHELL", "python -c \"import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000${var.health_check_path}', timeout=3).status == 200 else 1)\""]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 60
    }
  }])

  # Both attributes are STATED so the provider stops planning a replacement of
  # the task definition on every run: newer provider versions report
  # `enable_fault_injection` and the volume's `configure_at_launch` as
  # "known after apply" when they are left implicit, and a task definition
  # that is replaced on every plan hides the plans that matter.
  enable_fault_injection = false

  volume {
    name = "tmp"
    # No configuration block: an ephemeral volume backed by task storage,
    # which is what a read-only root filesystem needs and nothing more.
    configure_at_launch = false
  }

  tags = local.tags
}

resource "aws_ecs_service" "this" {
  name            = "sentinel-${var.name}"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.this.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = var.private_subnet_ids
    security_groups = [aws_security_group.tasks.id]
    # FALSE. Tasks reach AWS through VPC endpoints or NAT; a public IP on an
    # application task is an internet-addressable process.
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.this.arn
    container_name   = "sentinel"
    container_port   = 8000
  }

  # Long enough for a migration check plus worker startup. Too short and ECS
  # kills a task that was about to become healthy, in a loop.
  health_check_grace_period_seconds = 120

  deployment_circuit_breaker {
    enable = true
    # ROLLBACK. Without it a deployment of a broken image drains the healthy
    # tasks and leaves nothing serving.
    rollback = true
  }

  # 200/100 means a full parallel set comes up before any old task goes away:
  # a rolling deploy with no reduction in capacity.
  deployment_maximum_percent         = 200
  deployment_minimum_healthy_percent = 100

  enable_execute_command = false

  tags = local.tags

  depends_on = [aws_lb_listener.http]

  lifecycle {
    # The image digest changes on every release, and the release pipeline is
    # what changes it. Terraform noticing and reverting would make a deploy
    # race a configuration apply.
    ignore_changes = [task_definition, desired_count]
  }
}

# ── autoscaling ───────────────────────────────────────────────────────────

resource "aws_appautoscaling_target" "this" {
  service_namespace  = "ecs"
  resource_id        = "service/${aws_ecs_cluster.this.name}/${aws_ecs_service.this.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  min_capacity       = var.min_capacity
  max_capacity       = var.max_capacity
}

resource "aws_appautoscaling_policy" "cpu" {
  name               = "sentinel-${var.name}-cpu"
  policy_type        = "TargetTrackingScaling"
  service_namespace  = aws_appautoscaling_target.this.service_namespace
  resource_id        = aws_appautoscaling_target.this.resource_id
  scalable_dimension = aws_appautoscaling_target.this.scalable_dimension

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    # 60%, not 80%. Headroom matters more than utilisation for a service on
    # the authorization path: scaling out takes a minute and a queue of
    # pending authorizations is a queue of blocked agents.
    target_value       = 60
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}

# ── outputs ───────────────────────────────────────────────────────────────

output "cluster_name" {
  value = aws_ecs_cluster.this.name
}

output "service_name" {
  value = aws_ecs_service.this.name
}

output "alb_dns_name" {
  value = aws_lb.this.dns_name
}

output "alb_arn" {
  description = "Exported so the WAF module can associate with it."
  value       = aws_lb.this.arn
}

output "task_security_group_id" {
  description = "Pass to the database and cache modules as an allowed group."
  value       = aws_security_group.tasks.id
}

output "task_role_arn" {
  value = aws_iam_role.task.arn
}

output "listener_is_encrypted" {
  description = "False when no certificate was supplied. Reported rather than assumed."
  value       = local.encrypted
}

output "alb_arn_suffix" {
  description = <<-EOT
    The ALB's CloudWatch DIMENSION value, which is not its ARN.

    Exported separately because passing the full ARN to a CloudWatch alarm
    produces an alarm that never fires and sits in INSUFFICIENT_DATA forever —
    which reads as broken monitoring rather than as a wrong value, and so gets
    muted instead of fixed.
  EOT
  value       = aws_lb.this.arn_suffix
}
