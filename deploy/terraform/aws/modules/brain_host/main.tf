#############################################################################
# Sentinel — the brain host
#
# ONE small instance that runs the SAME image as the service, as the replica
# that drains the pipeline queue, on a host where the owner has installed and
# signed in to their advisor CLI. The Fargate replicas run with zero pipeline
# threads while this exists, so every incident's advisory note comes from
# here. The advisor is ADVISORY: it cannot move triage wherever it runs.
#
# WHY A HOST AND NOT THE TASK. The CLI authenticates as a signed-in person.
# A Fargate task has nobody to sign in, ECS Exec is refused by a read-only
# root filesystem, and copying a personal session into a secret would move a
# human credential somewhere its owner cannot see it used. A host the owner
# connects to through Session Manager keeps the sign-in theirs.
#
# THIS MODULE INSTALLS NO THIRD-PARTY SOFTWARE. The bootstrap installs the
# distribution's own container runtime and nothing else; it downloads no
# vendor installer. The owner places the CLI in /opt/agy themselves, in the
# same session in which they sign in, so what runs with their identity is
# something they chose to run. Until they do, the advisor reports itself
# unavailable and incidents are still processed by deterministic policy.
#
# The container's configuration is READ FROM THE ECS TASK DEFINITION at
# start (image digest, environment, secret references), so this host cannot
# drift from the service: restart the unit after a rollout and it is current.
#
# No inbound rule, no public address, no SSH key. IMDSv2 with a hop limit of
# one, so the container cannot reach the instance role.
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

variable "subnet_id" {
  description = "A PRIVATE subnet with outbound internet (NAT): the CLI calls its provider."
  type        = string
}

variable "security_group_id" {
  description = "The service's task security group, so the database and cache admit this host by the same group rule."
  type        = string
}

variable "instance_type" {
  type    = string
  default = "t4g.small"
}

variable "task_family" {
  description = "ECS task definition family to mirror (image, environment, secret references)."
  type        = string
}

variable "secrets_reader_policy_json" {
  description = "The secrets module's reader policy: the same secrets the task reads, no more."
  type        = string
}

variable "extra_secret_arns" {
  description = "Secrets the task definition references that live outside the secrets module (database DSN, cache URL)."
  type        = list(string)
  default     = []
}

variable "kms_key_arns" {
  description = "Keys needed to decrypt those secrets."
  type        = list(string)
}

variable "volume_kms_key_arn" {
  type = string
}

variable "advisor_model" {
  description = "A model name the owner's CLI offers."
  type        = string
}

variable "pipeline_workers" {
  type    = number
  default = 4
}

variable "tags" {
  type    = map(string)
  default = {}
}

locals {
  tags = merge(var.tags, {
    Project     = "sentinel"
    Environment = var.name
    Component   = "brain-host"
    ManagedBy   = "terraform"
  })
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# Looked up by name from Amazon's own account rather than through the public
# SSM parameter: the provisioning role holds no ssm:GetParameter, and this
# needs only ec2:DescribeImages.
data "aws_ami" "al2023_arm64" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-kernel-*-arm64"]
  }
  filter {
    name   = "architecture"
    values = ["arm64"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "this" {
  name               = "sentinel-${var.name}-brain-host"
  assume_role_policy = data.aws_iam_policy_document.assume.json
  tags               = local.tags
}

# Session Manager is the ONLY way in: no key pair, no inbound rule.
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.this.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "secrets" {
  name   = "read-the-task-secrets"
  role   = aws_iam_role.this.id
  policy = var.secrets_reader_policy_json
}

data "aws_iam_policy_document" "mirror" {
  statement {
    sid       = "ReadTheTaskDefinitionItMirrors"
    actions   = ["ecs:DescribeTaskDefinition"]
    resources = ["*"] # the action does not support resource-level permissions
  }
  statement {
    sid       = "PullTheImage"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"] # account-wide by design of the API
  }
  statement {
    sid       = "PullTheImageLayers"
    actions   = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"]
    resources = ["arn:aws:ecr:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:repository/sentinel-${var.name}"]
  }
  dynamic "statement" {
    for_each = length(var.extra_secret_arns) > 0 ? [1] : []
    content {
      sid       = "ReadTheDatastoreSecrets"
      actions   = ["secretsmanager:GetSecretValue"]
      resources = var.extra_secret_arns
    }
  }
  statement {
    sid       = "DecryptThoseSecrets"
    actions   = ["kms:Decrypt"]
    resources = var.kms_key_arns
  }
}

resource "aws_iam_role_policy" "mirror" {
  name   = "mirror-the-service"
  role   = aws_iam_role.this.id
  policy = data.aws_iam_policy_document.mirror.json
}

resource "aws_iam_instance_profile" "this" {
  name = "sentinel-${var.name}-brain-host"
  role = aws_iam_role.this.name
  tags = local.tags
}

resource "aws_instance" "this" {
  ami                         = data.aws_ami.al2023_arm64.id
  instance_type               = var.instance_type
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = [var.security_group_id]
  iam_instance_profile        = aws_iam_instance_profile.this.name
  associate_public_ip_address = false
  monitoring                  = false

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 20
    encrypted             = true
    kms_key_id            = var.volume_kms_key_arn
    delete_on_termination = true
  }

  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    region           = data.aws_region.current.name
    task_family      = var.task_family
    advisor_model    = var.advisor_model
    pipeline_workers = var.pipeline_workers
  })
  user_data_replace_on_change = true

  # A new AMI release must not replace a host somebody signed in to.
  lifecycle {
    ignore_changes = [ami]
  }

  tags = merge(local.tags, { Name = "sentinel-${var.name}-brain-host" })
}

output "instance_id" {
  value = aws_instance.this.id
}

output "cli_directory" {
  description = "Where the owner places their advisor CLI binary (named `agy`); mounted read-only into the container."
  value       = "/opt/agy"
}

output "sign_in_command" {
  description = "Run in a Session Manager session on the instance, once the CLI is in place, to sign it in."
  value       = "sudo -u sentinel env HOME=/var/lib/sentinel-agy /opt/agy/agy"
}
