#############################################################################
# Sentinel — PostgreSQL
#
# WHAT THIS COSTS, honestly, at the shipped defaults:
#   db.t4g.micro single-AZ    ~$12/month  (dev)
#   db.t4g.small multi-AZ     ~$50/month  (pilot)
#   db.m7g.large multi-AZ    ~$260/month  (production)
# Plus storage at $0.115/GB-month for gp3 and backup storage beyond the free
# allowance equal to the instance size.
#
# GRAVITON (t4g / m7g) THROUGHOUT. Roughly 20% cheaper than the equivalent
# x86 class for the same work, and PostgreSQL has no architecture-specific
# behaviour that makes it a risk.
#
# WHY POSTGRES AND NOT SQLITE IN ANY DEPLOYED ENVIRONMENT
# -------------------------------------------------------
# Row-level security. `Settings.from_environment` refuses to start in
# production against anything but Postgres, because tenant isolation here is
# enforced by RLS with FORCE and SQLite has no such layer — a cross-tenant
# query that RLS would bound returns everything on SQLite. That is asserted in
# `test_rls_alone_blocks_the_leak_with_the_application_predicate_removed`
# rather than assumed.
#
# THE PASSWORD IS GENERATED HERE AND NEVER PRINTED
# ------------------------------------------------
# `random_password` puts the value in Terraform state, which is unavoidable
# for a managed database — RDS has no "generate and never tell me" mode that
# also lets an application connect. What IS avoidable is putting it anywhere
# else: it goes straight into Secrets Manager, the output is marked sensitive,
# and `.gitignore` excludes state. Manage_master_user_password would move it
# into AWS's own rotation, and is the better answer where the engine supports
# it — offered as a flag rather than forced, because it changes how the
# application reads the credential.
#
# DELETION PROTECTION AND A FINAL SNAPSHOT ARE ON BY DEFAULT.
# `terraform destroy` on a production database should be annoying.
#############################################################################

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

variable "name" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "database_subnet_ids" {
  description = "The database tier. These subnets have NO default route by design."
  type        = list(string)

  validation {
    condition     = length(var.database_subnet_ids) >= 2
    error_message = "RDS requires a subnet group spanning at least two availability zones, even for a single-AZ instance."
  }
}

variable "allowed_security_group_ids" {
  description = <<-EOT
    Security groups permitted to reach 5432.

    A LIST OF GROUPS, never a CIDR. A CIDR rule stays correct-looking while the
    subnet it names gains new occupants; a group rule names the workload.
  EOT
  type        = list(string)
}

variable "kms_key_arn" {
  type = string
}

variable "secret_kms_key_arn" {
  type = string
}

variable "instance_class" {
  description = "Graviton by default: ~20% cheaper for the same work."
  type        = string
  default     = "db.t4g.micro"
}

variable "engine_version" {
  description = <<-EOT
    Major.minor pinned. An unpinned version upgrades under you during a
    maintenance window.

    A pin also EXPIRES: RDS retires minors, and the first apply of this
    stack (2026-09-24, ap-south-1) was refused with "Cannot find version
    16.4 for postgres". Check `aws rds describe-db-engine-versions --engine
    postgres` before a fresh deployment; 16.11 was the newest 16.x that
    db.t4g.micro offered on that date.
  EOT
  type        = string
  default     = "16.11"
}

variable "allocated_storage_gb" {
  type    = number
  default = 20
}

variable "max_allocated_storage_gb" {
  description = <<-EOT
    Storage autoscaling ceiling. Set equal to allocated_storage_gb to disable.

    A ceiling rather than unlimited growth: an ingest loop that writes
    unbounded rows should hit a wall and alarm, not silently grow a 20 GB
    volume to 6 TB and present the bill later.
  EOT
  type        = number
  default     = 100
}

variable "multi_az" {
  description = "Synchronous standby in a second AZ. Roughly doubles the instance cost and is what makes an AZ loss survivable."
  type        = bool
  default     = false
}

variable "backup_retention_days" {
  description = <<-EOT
    Automated backup retention, which is also the PITR window.

    ZERO DISABLES POINT-IN-TIME RECOVERY ENTIRELY, so it is refused. The DR
    drills in this repository (scripts/run_dr_postgres_wal_pitr_drill.py --archive-to s3)
    measure recovery against this window; a zero here makes those drills
    describe a capability the deployment does not have.
  EOT
  type        = number
  default     = 7

  validation {
    condition     = var.backup_retention_days >= 1
    error_message = "backup_retention_days of 0 disables point-in-time recovery. The DR drills in this repository measure against this window, so a zero would make them describe a capability that is not there."
  }
}

variable "manage_master_password_with_aws" {
  description = <<-EOT
    Let RDS generate and rotate the master password in Secrets Manager.

    Better than a Terraform-generated password, because the value never enters
    Terraform state at all. Off by default because it changes where the
    application reads the credential from, and turning it on for an existing
    instance is a migration rather than a flag.
  EOT
  type        = bool
  default     = false
}

variable "deletion_protection" {
  type    = bool
  default = true
}

variable "tags" {
  type    = map(string)
  default = {}
}

locals {
  tags = merge(var.tags, {
    Project   = "Sentinel"
    ManagedBy = "terraform"
    Component = "database"
  })
}

resource "aws_db_subnet_group" "this" {
  name       = "sentinel-${var.name}"
  subnet_ids = var.database_subnet_ids
  tags       = merge(local.tags, { Name = "${var.name}-db" })
}

resource "aws_security_group" "this" {
  name        = "sentinel-${var.name}-db"
  description = "PostgreSQL, reachable only from named application security groups"
  vpc_id      = var.vpc_id

  tags = merge(local.tags, { Name = "${var.name}-db" })
}

# One rule per permitted group. Referencing a security group rather than a
# CIDR means the rule keeps meaning "the application" as the application's
# addresses change.
resource "aws_vpc_security_group_ingress_rule" "postgres" {
  count = length(var.allowed_security_group_ids)

  security_group_id            = aws_security_group.this.id
  referenced_security_group_id = var.allowed_security_group_ids[count.index]
  description                  = "PostgreSQL from an application workload"
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

# THE OTHER HALF OF THE SAME PERMISSION. Security groups are evaluated on
# both ends: the rule above admits the workload here, and this one lets the
# workload's own group leave for this port. The application group permits
# egress to 443 only, so without this rule every connection to the PostgreSQL
# endpoint timed out -- found on the first real deployment of this stack
# (2026-09-24). Owned here, beside the ingress rule it completes, so the two
# cannot drift apart.
resource "aws_vpc_security_group_egress_rule" "postgres_from_workload" {
  count = length(var.allowed_security_group_ids)

  security_group_id            = var.allowed_security_group_ids[count.index]
  referenced_security_group_id = aws_security_group.this.id
  description                  = "PostgreSQL: this workload may reach the postgres group"
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

# NO EGRESS RULE AT ALL.
#
# Deliberately absent, which in a VPC security group means no outbound traffic
# is permitted. A database does not initiate connections. Combined with the
# database subnets having no default route, there are two independent reasons
# this instance cannot reach the internet.

resource "random_password" "master" {
  count = var.manage_master_password_with_aws ? 0 : 1

  length = 40
  # URL-UNRESERVED specials only. RDS rejects several punctuation characters
  # with an error that does not name which one, and a DSN rejects others
  # unless percent-encoded: the first real deployment generated `%`, `)` and
  # `}` and the driver refused the URL. Forty characters over 66 symbols is
  # still ~240 bits; nothing is lost by leaving punctuation out.
  override_special = "-_.~"
}

resource "aws_db_parameter_group" "this" {
  name   = "sentinel-${var.name}-pg16"
  family = "postgres16"

  # SSL REQUIRED. Without this a client can negotiate plaintext and the
  # connection still works, so the insecure path is the silent one.
  parameter {
    name         = "rds.force_ssl"
    value        = "1"
    apply_method = "pending-reboot"
  }

  # Log every statement that takes over a second. Not `log_statement = all`,
  # which on a busy instance costs more in CloudWatch ingestion than the
  # database costs to run, and buries the slow query in noise.
  parameter {
    name  = "log_min_duration_statement"
    value = "1000"
  }

  # Log every DDL. A schema change nobody recorded is the hardest kind of
  # incident to reconstruct, and the volume is negligible.
  parameter {
    name  = "log_statement"
    value = "ddl"
  }

  parameter {
    name  = "log_connections"
    value = "1"
  }

  parameter {
    name  = "log_disconnections"
    value = "1"
  }

  tags = local.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_db_instance" "this" {
  identifier = "sentinel-${var.name}"

  engine         = "postgres"
  engine_version = var.engine_version
  instance_class = var.instance_class

  # gp3, not gp2: same price per GB with a baseline 3,000 IOPS included rather
  # than 3 IOPS/GB, so a 20 GB volume is not limited to 60 IOPS.
  storage_type          = "gp3"
  allocated_storage     = var.allocated_storage_gb
  max_allocated_storage = var.max_allocated_storage_gb > var.allocated_storage_gb ? var.max_allocated_storage_gb : null

  storage_encrypted = true
  kms_key_id        = var.kms_key_arn

  db_name  = "sentinel"
  username = "sentinel"

  manage_master_user_password   = var.manage_master_password_with_aws ? true : null
  master_user_secret_kms_key_id = var.manage_master_password_with_aws ? var.secret_kms_key_arn : null
  password                      = var.manage_master_password_with_aws ? null : random_password.master[0].result

  db_subnet_group_name   = aws_db_subnet_group.this.name
  vpc_security_group_ids = [aws_security_group.this.id]
  parameter_group_name   = aws_db_parameter_group.this.name

  # FALSE, and there is no variable to change it. A publicly-addressable
  # database is not a configuration this module offers.
  publicly_accessible = false

  multi_az = var.multi_az

  backup_retention_period = var.backup_retention_days
  # 03:00-04:00 UTC, before the 04:00-05:00 maintenance window, so a backup
  # completes before a patch might restart the instance.
  backup_window      = "03:00-04:00"
  maintenance_window = "sun:04:00-sun:05:00"

  copy_tags_to_snapshot = true

  # Minor versions applied in the window; MAJOR versions never automatically.
  # A major upgrade can change query plans and break RLS behaviour, and it
  # should happen when somebody is watching.
  auto_minor_version_upgrade  = true
  allow_major_version_upgrade = false

  deletion_protection       = var.deletion_protection
  skip_final_snapshot       = false
  final_snapshot_identifier = "sentinel-${var.name}-final"

  performance_insights_enabled    = true
  performance_insights_kms_key_id = var.kms_key_arn
  # SEVEN DAYS IS THE FREE TIER. Beyond that Performance Insights is billed
  # per vCPU per month, which is easy to enable and forget.
  performance_insights_retention_period = 7

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  tags = merge(local.tags, { Name = "sentinel-${var.name}" })

  lifecycle {
    # The password is set once. Rotation happens in Secrets Manager or through
    # AWS-managed rotation, not by Terraform noticing drift and replacing the
    # value the application is currently using.
    ignore_changes = [password]
  }
}

resource "aws_secretsmanager_secret" "dsn" {
  name        = "sentinel/${var.name}/database-url"
  description = "SENTINEL_DATABASE_URL. Written by this module because it is the only place that knows the generated password."
  kms_key_id  = var.secret_kms_key_arn

  recovery_window_in_days = 30
  tags                    = local.tags
}

resource "aws_secretsmanager_secret_version" "dsn" {
  count = var.manage_master_password_with_aws ? 0 : 1

  secret_id = aws_secretsmanager_secret.dsn.id
  # `sslmode=require` in the DSN as well as `rds.force_ssl` on the server.
  # Either alone is enough; both means neither a server parameter reset nor a
  # client library default silently downgrades the connection.
  # The password is URL-ENCODED into the DSN. The first real deployment
  # generated one containing `%`, `)` and `}`; the driver refused the URL
  # ("invalid percent-encoded token") and quoted the password back in its
  # error. The generator below is also restricted to URL-safe specials so
  # the encoding is a second guard rather than the only one.
  secret_string = format(
    "postgresql://%s:%s@%s:%d/%s?sslmode=require",
    aws_db_instance.this.username,
    urlencode(random_password.master[0].result),
    aws_db_instance.this.address,
    aws_db_instance.this.port,
    aws_db_instance.this.db_name,
  )

  # SET ONCE, LIKE THE INSTANCE PASSWORD ABOVE. The instance ignores password
  # drift; if this version followed `random_password` on its own, a change to
  # the generator would rotate the DSN but not the database, and every
  # connection would fail "password authentication failed" -- which is what
  # happened on the first real deployment (2026-09-24). Rotation is a Secrets
  # Manager operation applied to BOTH, never a Terraform diff on one.
  lifecycle {
    ignore_changes = [secret_string]
  }
}

output "endpoint" {
  value = aws_db_instance.this.endpoint
}

output "security_group_id" {
  value = aws_security_group.this.id
}

output "dsn_secret_arn" {
  value = aws_secretsmanager_secret.dsn.arn
}

output "master_secret_arn" {
  description = "Set only when AWS manages the password. Empty otherwise."
  value       = var.manage_master_password_with_aws ? aws_db_instance.this.master_user_secret[0].secret_arn : ""
}

output "pitr_window_days" {
  description = "The window the DR drills measure against."
  value       = var.backup_retention_days
}

output "instance_arn" {
  description = "For the AWS Backup selection. Its recovery points survive deletion of this instance, which RDS automated backups do not."
  value       = aws_db_instance.this.arn
}
