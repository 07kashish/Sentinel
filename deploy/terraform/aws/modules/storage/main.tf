#############################################################################
# Sentinel — storage
#
# WHAT THIS COSTS: pennies. The evidence bucket holds ~200-byte transparency
# roots at one write per day; `sentinel/infrastructure/s3_root_sink.py` puts
# the annual figure at $0.002 and there is a function in the codebase that
# computes it so the number is checkable rather than asserted.
#
# THE EVIDENCE BUCKET IS THE POINT, AND IT HAS ONE IRREVERSIBLE PROPERTY
# ----------------------------------------------------------------------
# Object Lock in COMPLIANCE mode puts an object beyond the reach of the
# operator: nobody can delete or overwrite a locked version before its
# retention date, including the account root and AWS support. That is the only
# reason to involve S3 at all — it moves the transparency root out of the
# control of the party that writes it.
#
# GOVERNANCE mode is the trap. It looks identical in the console and any
# principal holding `s3:BypassGovernanceRetention` can delete the object, so a
# root written that way is still the operator's to remove and
# `is_independently_verifiable` would be reporting a guarantee that is not
# there. This module writes COMPLIANCE and nothing else.
#
# `object_lock_enabled` CANNOT BE ADDED AFTER CREATION. If it is forgotten the
# fix is a new bucket; there is no setting to turn on afterwards. This is the
# mistake everyone makes once, and the sink reports it specifically when a PUT
# returns 400.
#
# COMPLIANCE MODE IS ALSO IRREVERSIBLE IN THE OTHER DIRECTION: a retention
# period cannot be shortened. Think about `evidence_retention_days` before
# applying, not after.
#
# NOT GLACIER, DELIBERATELY. Glacier bills a 40 KB minimum per object and a
# 90-180 day minimum duration. Against a 200-byte root that is roughly 200x
# more expensive than Standard. Cheap-sounding storage classes are a trap at
# this object size, so the lifecycle rules below transition the ARTIFACT
# bucket and leave evidence in Standard.
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

variable "evidence_kms_key_arn" {
  description = "CMK for the evidence bucket. Separate from the data key."
  type        = string
}

variable "artifacts_kms_key_arn" {
  description = <<-EOT
    CMK for the release-artifacts bucket. Artifacts are signed builds, not
    evidence, so they share the DATA key rather than the evidence key -- the
    four-key split exists so that whoever can decrypt evidence cannot by that
    fact decrypt everything else, and artifacts belong on the other side of
    that line. AES256 (SSE-S3) was used before; it encrypts, but with a key
    nobody can revoke, audit or scope, which is why the policy scanner flagged
    it.
  EOT
  type        = string
}

variable "evidence_retention_days" {
  description = <<-EOT
    Days a transparency root is locked. IRREVERSIBLE once applied: compliance
    retention cannot be shortened.

    3650 (ten years) is the default because an auditor checking a root from
    last year needs it still locked, and at 200 bytes a day ten years is about
    0.7 MB. Lower it only with a reason you would state to that auditor.
  EOT
  type        = number
  default     = 3650

  validation {
    condition     = var.evidence_retention_days >= 1
    error_message = "a retention shorter than one day is not a retention guarantee."
  }
}

variable "artifact_retention_days" {
  description = "Days release artifacts are kept before expiry. Not locked."
  type        = number
  default     = 365
}

variable "tags" {
  type    = map(string)
  default = {}
}

locals {
  tags = merge(var.tags, {
    Project   = "Sentinel"
    ManagedBy = "terraform"
    Component = "storage"
  })
}

data "aws_caller_identity" "current" {}

# ── the evidence bucket ────────────────────────────────────────────────────

resource "aws_s3_bucket" "evidence" {
  # Account id in the name because S3 bucket names are globally unique across
  # every AWS customer, and "sentinel-evidence" is taken.
  bucket = "sentinel-${var.name}-evidence-${data.aws_caller_identity.current.account_id}"

  # CANNOT BE ADDED LATER. Forgetting this means creating a new bucket.
  object_lock_enabled = true

  tags = merge(local.tags, { Name = "${var.name}-evidence", Worm = "compliance" })
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  versioning_configuration {
    # Object Lock REQUIRES versioning. A locked write always returns a version
    # id, and the sink refuses to record a publication that came back without
    # one — because the absence means the object is not locked.
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.evidence_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.evidence]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.evidence_kms_key_arn
    }
    # Reuses one data key across objects in the same prefix, cutting KMS
    # request charges. Safe here and worth having on a bucket written once a
    # day for ten years.
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# NO LIFECYCLE TRANSITION ON EVIDENCE.
#
# Deliberately absent. Transitioning 200-byte objects to Glacier costs roughly
# 200x more than leaving them in Standard, because of the 40 KB minimum
# billable size. The obvious cost optimisation is the expensive choice here.

resource "aws_s3_bucket_policy" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyUnencryptedTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.evidence.arn,
          "${aws_s3_bucket.evidence.arn}/*",
        ]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        # Belt and braces against the GOVERNANCE trap: even if somebody later
        # writes an object with a governance retention, nobody can bypass it
        # through this bucket.
        Sid       = "DenyGovernanceBypass"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:BypassGovernanceRetention"
        Resource  = "${aws_s3_bucket.evidence.arn}/*"
      },
    ]
  })
}

# ── the artifact bucket ────────────────────────────────────────────────────
#
# Release artifacts, SBOMs and scan reports. NOT locked: these are rebuildable
# from a commit, and locking them would mean paying to store every build of
# every branch for a decade.

resource "aws_s3_bucket" "artifacts" {
  bucket = "sentinel-${var.name}-artifacts-${data.aws_caller_identity.current.account_id}"
  tags   = merge(local.tags, { Name = "${var.name}-artifacts" })
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.artifacts_kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    id     = "expire-old-artifacts"
    status = "Enabled"

    filter {}

    expiration { days = var.artifact_retention_days }

    # Incomplete multipart uploads are invisible in the console and billed.
    # This is the single most commonly forgotten S3 cost.
    abort_incomplete_multipart_upload { days_after_initiation = 7 }

    noncurrent_version_expiration { noncurrent_days = 30 }
  }
}

resource "aws_s3_bucket_policy" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyUnencryptedTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.artifacts.arn,
        "${aws_s3_bucket.artifacts.arn}/*",
      ]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}

# ── outputs ────────────────────────────────────────────────────────────────

output "evidence_bucket" {
  value = aws_s3_bucket.evidence.id
}

output "evidence_bucket_arn" {
  value = aws_s3_bucket.evidence.arn
}

output "artifact_bucket" {
  value = aws_s3_bucket.artifacts.id
}

output "publisher_policy_json" {
  description = <<-EOT
    The MINIMAL policy for the transparency publisher: two S3 actions on one prefix, plus encrypting under the bucket's key.

    `s3:PutObjectRetention` is the one people leave out, and its absence
    produces a 403 that reads like a bucket problem. No GetObject, no
    ListBucket, no DeleteObject — the sink never reads and never lists, and a
    credential that can delete defeats the purpose of the lock.
  EOT
  value = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "PublishTransparencyRootsOnly"
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:PutObjectRetention"]
        Resource = "${aws_s3_bucket.evidence.arn}/sentinel/transparency/*"
      },
      {
        # The bucket encrypts with a customer-managed key, so a PutObject also
        # needs to generate a data key under it. Without this the first real
        # publication failed with a 403 whose text blamed retention. One key,
        # two actions; no key administration.
        Sid      = "EncryptWhatIsPublished"
        Effect   = "Allow"
        Action   = ["kms:GenerateDataKey", "kms:Encrypt"]
        Resource = var.evidence_kms_key_arn
      }
    ]
  })
}
