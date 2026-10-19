#############################################################################
# Sentinel — network
#
# WHAT THIS COSTS, AND THE ONE DECISION THAT DOMINATES IT
# -------------------------------------------------------
# A NAT Gateway is ~$32/month per availability zone in hourly charges before
# a single byte moves, plus $0.045/GB processed. Three AZs of NAT is ~$100/month
# to run an idle environment, and it is the single largest line item in a small
# AWS footprint — larger than the database.
#
# So `enable_nat_gateway` defaults to FALSE and the private subnets reach AWS
# services through VPC endpoints instead:
#
#   * Gateway endpoints for S3 and DynamoDB are FREE. No hourly charge, no
#     data processing charge.
#   * Interface endpoints are ~$7.20/month each per AZ, which is cheaper than
#     NAT only because we need a handful rather than general egress.
#
# The trade-off is stated rather than hidden: with NAT disabled, tasks in
# private subnets CANNOT reach the public internet. That is a security
# improvement and an operational constraint. A deployment that must call an
# external model provider, a webhook, or an OIDC issuer on the public internet
# needs `enable_nat_gateway = true`, and the pilot/production environments say
# which they chose and why.
#
# WHY THE DATABASE SUBNETS ARE SEPARATE FROM THE APPLICATION SUBNETS
# -------------------------------------------------------------------
# Both are private. Separating them means a security group rule can name a
# subnet tier rather than a CIDR somebody has to keep in their head, and it
# means an RDS subnet group cannot accidentally include a subnet that later
# gains a route to a NAT Gateway.
#
# NOTHING HERE IS APPLIED BY THIS REPOSITORY. `terraform validate` and
# `terraform plan` are the evidence; `apply` is an operator decision with a
# bill attached.
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
  description = "Environment name, used as a prefix on every resource."
  type        = string
}

variable "cidr_block" {
  description = "VPC CIDR. /16 leaves room for three tiers across three AZs."
  type        = string
  default     = "10.42.0.0/16"

  validation {
    # A /24 or smaller cannot be subdivided into three tiers across three AZs
    # without overlapping, and the failure surfaces as an opaque CIDR error
    # halfway through an apply rather than here.
    condition     = tonumber(split("/", var.cidr_block)[1]) <= 20
    error_message = "cidr_block must be /20 or larger to hold three tiers across three AZs."
  }
}

variable "availability_zones" {
  description = "AZs to spread across. Two is the minimum for RDS multi-AZ."
  type        = list(string)

  validation {
    condition     = length(var.availability_zones) >= 2
    error_message = "at least two availability zones are required; RDS multi-AZ and an ALB both need them, and a single-AZ deployment cannot survive an AZ loss."
  }
}

variable "enable_nat_gateway" {
  description = <<-EOT
    Give private subnets egress to the public internet.

    FALSE by default because NAT is the largest line item in a small AWS
    footprint: ~$32/month per AZ before any traffic. With it false, private
    tasks reach AWS services through VPC endpoints and cannot reach the public
    internet at all.

    Set true only if this deployment must call something on the public internet
    — an external model provider, a customer webhook, a public OIDC issuer.
  EOT
  type        = bool
  default     = false
}

variable "single_nat_gateway" {
  description = <<-EOT
    Put one NAT Gateway in one AZ instead of one per AZ.

    Cuts the cost by the number of AZs and introduces a single point of failure
    whose blast radius is "all private egress". Defensible in dev, not in
    production — which is why it is a separate flag rather than folded into
    enable_nat_gateway.
  EOT
  type        = bool
  default     = true
}

variable "interface_endpoints" {
  description = <<-EOT
    AWS services to reach privately, without NAT.

    Each is ~$7.20/month per AZ, so the list is short on purpose and every
    entry is one a Fargate task genuinely needs:

      ecr.api / ecr.dkr — pull the container image
      logs              — ship logs to CloudWatch
      secretsmanager    — read the database credential
      kms               — decrypt that credential
      sqs               — the work queue
    Add xray only when tracing is on; it is not free and not required to boot.
  EOT
  type        = list(string)
  default = [
    "ecr.api",
    "ecr.dkr",
    "logs",
    "secretsmanager",
    "kms",
    "sqs",
  ]
}

variable "tags" {
  type    = map(string)
  default = {}
}

locals {
  az_count = length(var.availability_zones)

  # /20 VPC split three ways. `cidrsubnet` with a 4-bit offset gives 16
  # blocks, allocated as public / private / database with room to spare, so
  # adding a fourth tier later does not require renumbering the first three.
  public_cidrs = [
    for index in range(local.az_count) : cidrsubnet(var.cidr_block, 4, index)
  ]
  private_cidrs = [
    for index in range(local.az_count) : cidrsubnet(var.cidr_block, 4, index + 4)
  ]
  database_cidrs = [
    for index in range(local.az_count) : cidrsubnet(var.cidr_block, 4, index + 8)
  ]

  nat_count = var.enable_nat_gateway ? (var.single_nat_gateway ? 1 : local.az_count) : 0

  tags = merge(var.tags, {
    Project   = "Sentinel"
    ManagedBy = "terraform"
    Component = "network"
  })
}

resource "aws_vpc" "this" {
  cidr_block = var.cidr_block

  # Both required for interface VPC endpoints to resolve to private addresses.
  # Without them the endpoint exists and nothing uses it, which looks like a
  # working configuration and is not.
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = merge(local.tags, { Name = "${var.name}-vpc" })
}

# FLOW LOGS ARE ON, TO CLOUDWATCH, WITH A SHORT RETENTION.
#
# On because "which task talked to what" is the first question in an incident
# and it cannot be answered retroactively. Short retention because flow logs
# are voluminous and their value decays fast: 14 days covers an investigation
# and costs cents, where indefinite retention on a busy VPC is a real bill.
resource "aws_cloudwatch_log_group" "flow" {
  name              = "/aws/vpc/${var.name}/flow"
  retention_in_days = var.flow_log_retention_days
  kms_key_id        = var.log_kms_key_arn
  tags              = local.tags
}

variable "flow_log_retention_days" {
  description = "Flow log retention. Short on purpose; their value decays fast."
  type        = number
  default     = 14
}

variable "log_kms_key_arn" {
  description = "CMK for the flow log group. Empty uses the AWS-managed key."
  type        = string
  default     = ""
}

resource "aws_iam_role" "flow" {
  name = "${var.name}-vpc-flow-logs"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        # Confused-deputy protection. Without these, any account's flow logs
        # could name this role.
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnLike      = { "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:vpc-flow-log/*" }
      }
    }]
  })

  tags = local.tags
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

resource "aws_iam_role_policy" "flow" {
  name = "write-flow-logs"
  role = aws_iam_role.flow.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogStreams",
      ]
      # Scoped to THIS log group. `Resource: "*"` here would let the role
      # write into any log group in the account, including the audit ones.
      Resource = "${aws_cloudwatch_log_group.flow.arn}:*"
    }]
  })
}

resource "aws_flow_log" "this" {
  vpc_id               = aws_vpc.this.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.flow.arn
  iam_role_arn         = aws_iam_role.flow.arn
  tags                 = local.tags
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { Name = "${var.name}-igw" })
}

resource "aws_subnet" "public" {
  count = local.az_count

  vpc_id            = aws_vpc.this.id
  cidr_block        = local.public_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  # FALSE, deliberately. A public subnet is for the load balancer and the NAT
  # Gateway, not for application tasks. Auto-assigning public IPs makes it one
  # forgotten flag away from putting a task directly on the internet.
  map_public_ip_on_launch = false

  tags = merge(local.tags, {
    Name = "${var.name}-public-${var.availability_zones[count.index]}"
    Tier = "public"
  })
}

resource "aws_subnet" "private" {
  count = local.az_count

  vpc_id            = aws_vpc.this.id
  cidr_block        = local.private_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = merge(local.tags, {
    Name = "${var.name}-private-${var.availability_zones[count.index]}"
    Tier = "private"
  })
}

resource "aws_subnet" "database" {
  count = local.az_count

  vpc_id            = aws_vpc.this.id
  cidr_block        = local.database_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = merge(local.tags, {
    Name = "${var.name}-database-${var.availability_zones[count.index]}"
    Tier = "database"
  })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { Name = "${var.name}-public" })
}

resource "aws_route" "public_default" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public" {
  count = local.az_count

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_eip" "nat" {
  count  = local.nat_count
  domain = "vpc"
  tags   = merge(local.tags, { Name = "${var.name}-nat-${count.index}" })
}

resource "aws_nat_gateway" "this" {
  count = local.nat_count

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  tags          = merge(local.tags, { Name = "${var.name}-nat-${count.index}" })

  depends_on = [aws_internet_gateway.this]
}

# One private route table per AZ even with a single NAT, so switching
# `single_nat_gateway` to false later changes a route rather than restructuring
# the module.
resource "aws_route_table" "private" {
  count = local.az_count

  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { Name = "${var.name}-private-${count.index}" })
}

resource "aws_route" "private_default" {
  count = var.enable_nat_gateway ? local.az_count : 0

  route_table_id         = aws_route_table.private[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id = aws_nat_gateway.this[
    var.single_nat_gateway ? 0 : count.index
  ].id
}

resource "aws_route_table_association" "private" {
  count = local.az_count

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# THE DATABASE TIER HAS NO DEFAULT ROUTE AT ALL.
#
# Not "no NAT" — no route to 0.0.0.0/0 in any configuration. A database does
# not initiate outbound connections to the internet, and a subnet with no path
# there cannot be made to exfiltrate over one by a security group mistake.
resource "aws_route_table" "database" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { Name = "${var.name}-database" })
}

resource "aws_route_table_association" "database" {
  count = local.az_count

  subnet_id      = aws_subnet.database[count.index].id
  route_table_id = aws_route_table.database.id
}

# ── VPC endpoints: the reason NAT can stay off ──────────────────────────────

# FREE. Gateway endpoints have no hourly or data charge, which is why S3 access
# from a private subnet costs nothing and general internet egress costs $32/mo
# per AZ.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"

  route_table_ids = concat(
    aws_route_table.private[*].id,
    [aws_route_table.database.id],
  )

  tags = merge(local.tags, { Name = "${var.name}-s3" })
}

resource "aws_security_group" "endpoints" {
  name        = "${var.name}-vpc-endpoints"
  description = "HTTPS from inside the VPC to interface endpoints"
  vpc_id      = aws_vpc.this.id

  tags = merge(local.tags, { Name = "${var.name}-vpc-endpoints" })
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_https" {
  security_group_id = aws_security_group.endpoints.id
  description       = "HTTPS from within the VPC only"

  # The VPC CIDR, not 0.0.0.0/0. An interface endpoint is reachable only from
  # inside the VPC anyway, but a rule that says so cannot be widened by
  # attaching the group somewhere else.
  cidr_ipv4   = var.cidr_block
  from_port   = 443
  to_port     = 443
  ip_protocol = "tcp"
}

resource "aws_vpc_endpoint" "interface" {
  for_each = toset(var.interface_endpoints)

  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.${each.value}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true

  tags = merge(local.tags, { Name = "${var.name}-${each.value}" })
}

# ── outputs ────────────────────────────────────────────────────────────────

output "vpc_id" {
  value = aws_vpc.this.id
}

output "vpc_cidr" {
  value = aws_vpc.this.cidr_block
}

output "public_subnet_ids" {
  value = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

output "database_subnet_ids" {
  value = aws_subnet.database[*].id
}

output "has_internet_egress" {
  description = <<-EOT
    Whether private subnets can reach the public internet.

    Exported so a dependent module can REFUSE rather than hang: a task that
    needs an external OIDC issuer and is placed in a subnet with no route
    fails with a connection timeout at request time, which reads like an
    outage rather than a configuration choice.
  EOT
  value       = var.enable_nat_gateway
}

output "monthly_nat_cost_estimate_usd" {
  description = "ESTIMATED, not measured. Hourly charges only; excludes data processing."
  value       = local.nat_count * 32
}
