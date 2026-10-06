#--------------------------------------------------------------
# GuardDuty — bc-ctrl (account 929026881368, eu-west-1)
#
# DETECTOR OWNERSHIP: org-managed (delegated admin = account
# 957996720803, Control Tower / Landing Zone). A detector already
# exists in this account (ID b2cf34a7d246cd6457f9393c39b8376a,
# Status ENABLED). Terraform MUST NOT create or manage the detector
# or any detector feature — doing so produces:
#   BadRequestException: The request is rejected because a detector
#   already exists for the current account.
# We reference it via `data "aws_guardduty_detector" "existing"` and
# only manage our publishing destination, KMS CMK, and budget alert.
#
# FEATURE POSTURE (set by org admin — we cannot change these):
#   ENABLED  (included in base price):
#     - CloudTrail management event analysis
#     - VPC Flow Log analysis
#     - DNS query log analysis
#   DISABLED paid add-ons (admin-controlled, matches our intent):
#     - RUNTIME_MONITORING      (redundant with Falco+Tetragon)
#     - EKS_AUDIT_LOGS          (not needed here)
#     - EBS_MALWARE_PROTECTION  (expensive per-GB scan)
#     - RDS_LOGIN_EVENTS        (no RDS in this account)
#     - LAMBDA_NETWORK_LOGS     (no Lambda network flows of interest)
#     - S3_DATA_EVENTS          (mgmt events only)
#
# WHAT THIS FILE MANAGES:
#   1. data.aws_guardduty_detector.existing — read-only reference
#   2. aws_kms_key.guardduty + alias        — CMK for findings encryption
#   3. aws_s3_bucket_policy.guardduty_logs  — grants GuardDuty write
#   4. aws_guardduty_publishing_destination.s3 — findings → S3 bucket
#   5. aws_budgets_budget.monthly_ceiling   — $30/mo cost ceiling
#
# Budget alert: aws_budgets_budget (not Cost Anomaly Detection).
# Rationale: a hard monthly ceiling across the full account gives an
# early warning if any resource drifts. $30/mo with 80%+100% email
# alerts is simple, zero extra cost, and covers GuardDuty creep as
# well as any other runaway resource.
#
# Wazuh ingestion path:
#   GuardDuty → s3:PutObject → aws_s3_bucket.guardduty_logs (bc-guardduty-logs-*)
#   Wazuh EC2 → s3:GetObject+s3:ListBucket (granted in wazuh-ec2.tf S3LogBucketsReadOnly Sid)
#--------------------------------------------------------------

###############################################################
# Data source — reference the org-managed detector
#
# `data "aws_guardduty_detector"` with no arguments queries the
# current account + region and returns the active detector.
# This form has been valid since hashicorp/aws v4.x and is fully
# supported by the ">= 6.23" constraint in terraform_config.tf.
# The data source exposes: id, finding_publishing_frequency, status.
###############################################################

data "aws_guardduty_detector" "existing" {}

###############################################################
# KMS CMK — GuardDuty findings encryption
#
# GuardDuty requires a CMK for publishing destinations.
# The key policy grants:
#   1. Root account full admin (standard AWS requirement).
#   2. guardduty.amazonaws.com  GenerateDataKey + Encrypt, scoped
#      to this account (aws:SourceAccount) and this detector ARN
#      (aws:SourceArn) — prevents confused-deputy attacks.
#   3. Wazuh EC2 role Decrypt via kms:ViaService=s3 — restricts
#      the grant to S3 GetObject calls only.
###############################################################

resource "aws_kms_key" "guardduty" {
  description             = "CMK for GuardDuty findings encryption — bc-ctrl"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RootFullAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "GuardDutyEncrypt"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Encrypt"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
            "aws:SourceArn"     = "arn:aws:guardduty:${local.region}:${data.aws_caller_identity.current.account_id}:detector/${data.aws_guardduty_detector.existing.id}"
          }
        }
      },
      {
        # Wazuh EC2 role needs Decrypt to read the encrypted findings objects from S3.
        # kms:ViaService restricts the grant to S3 GetObject calls only — the Wazuh
        # role cannot use this key for arbitrary KMS Decrypt operations outside of S3.
        Sid    = "WazuhDecrypt"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.wazuh_ec2.arn
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.${local.region}.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = merge(local.common_tags, { Name = "guardduty-cmk" })
}

resource "aws_kms_alias" "guardduty" {
  name          = "alias/guardduty-bc-ctrl"
  target_key_id = aws_kms_key.guardduty.key_id
}

###############################################################
# S3 Bucket Policy — grants GuardDuty write access
#
# The bucket (aws_s3_bucket.guardduty_logs) and its public-access
# block already exist in s3-log-buckets.tf. A service-principal
# bucket policy is fully compatible with block_public_policy=true
# because that setting only blocks ACL-based public access, not
# service-principal statements.
#
# Statements:
#   1. GetBucketLocation — GuardDuty calls this before publishing.
#   2. PutObject         — findings delivery, scoped to bucket-owner-full-control
#                          ACL and this account (prevents cross-account injection).
###############################################################

resource "aws_s3_bucket_policy" "guardduty_logs" {
  bucket = aws_s3_bucket.guardduty_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "GuardDutyGetBucketLocation"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action   = "s3:GetBucketLocation"
        Resource = aws_s3_bucket.guardduty_logs.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
            "aws:SourceArn"     = "arn:aws:guardduty:${local.region}:${data.aws_caller_identity.current.account_id}:detector/${data.aws_guardduty_detector.existing.id}"
          }
        }
      },
      {
        Sid    = "GuardDutyPutObject"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.guardduty_logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"      = "bucket-owner-full-control"
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
            "aws:SourceArn"     = "arn:aws:guardduty:${local.region}:${data.aws_caller_identity.current.account_id}:detector/${data.aws_guardduty_detector.existing.id}"
          }
        }
      }
    ]
  })

  # Public access block must exist before the policy is attached.
  depends_on = [aws_s3_bucket_public_access_block.guardduty_logs]
}

###############################################################
# GuardDuty Publishing Destination — S3
#
# depends_on the bucket policy so GuardDuty can validate write
# access at creation time (it performs a test-write during resource
# creation; if the bucket policy is missing the creation fails).
# The KMS key is referenced via kms_key_arn — that implicit
# dependency is sufficient; no need to list it in depends_on.
#
# RESIDUAL RISK — org SCP: a member account CAN call
# guardduty:CreatePublishingDestination on its own detector (AWS
# docs confirm this is delegated to member accounts). However, if
# the org SCP at account 957996720803 explicitly denies this action,
# the next apply will fail on THIS resource specifically with
# AccessDenied. Fallback: route findings via EventBridge → SQS →
# Wazuh aws-sqs module (no guardduty:CreatePublishingDestination
# permission required, and EventBridge has native GD integration).
###############################################################

resource "aws_guardduty_publishing_destination" "s3" {
  detector_id      = data.aws_guardduty_detector.existing.id
  destination_type = "S3"
  destination_arn  = aws_s3_bucket.guardduty_logs.arn
  kms_key_arn      = aws_kms_key.guardduty.arn

  depends_on = [aws_s3_bucket_policy.guardduty_logs]
}

###############################################################
# Budget Alert — monthly cost ceiling
#
# Choice: aws_budgets_budget (not Cost Anomaly Detection).
# Rationale in file header above.
#
# $30/mo ceiling covers current baseline (~$3-4 GuardDuty) with
# comfortable headroom. Notifications fire at 80% ($24 actual)
# and 100% ($30 actual) so there is time to react before overage.
# COST type = billed charges (not forecasted), which avoids false
# positives from forecast variance.
###############################################################

resource "aws_budgets_budget" "monthly_ceiling" {
  name         = "bc-ctrl-monthly-ceiling"
  budget_type  = "COST"
  limit_amount = "30"
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = ["afonso3marques@gmail.com"]
  }

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = ["afonso3marques@gmail.com"]
  }

  tags = merge(local.common_tags, { Name = "bc-ctrl-monthly-ceiling" })
}
