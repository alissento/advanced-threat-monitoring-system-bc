#--------------------------------------------------------------
# Wazuh all-in-one EC2 deployment — bc-ctrl
#
# Single t3.xlarge instance running Manager + Indexer + Dashboard.
# Agents in bc-prd reach wazuh on ports 1514/1515 via VPC peering.
#--------------------------------------------------------------

###############################################################
# Security Group
###############################################################

resource "aws_security_group" "wazuh_ec2" {
  name        = "wazuh-ec2-sg"
  description = "Wazuh EC2 all-in-one - manager, indexer, dashboard"
  vpc_id      = module.vpc.vpc_id

  # Wazuh agent events from bc-prd (via VPC peering)
  ingress {
    description = "Wazuh agent events from bc-prd"
    from_port   = 1514
    to_port     = 1514
    protocol    = "tcp"
    cidr_blocks = [local.prd_vpc_cidr]
  }

  # Wazuh agent enrollment from bc-prd (via VPC peering)
  ingress {
    description = "Wazuh agent enrollment from bc-prd"
    from_port   = 1515
    to_port     = 1515
    protocol    = "tcp"
    cidr_blocks = [local.prd_vpc_cidr]
  }

  # Wazuh agent events from bc-ctrl
  ingress {
    description = "Wazuh agent events from bc-ctrl"
    from_port   = 1514
    to_port     = 1514
    protocol    = "tcp"
    cidr_blocks = [local.vpc_cidr]
  }

  # Wazuh agent enrollment from bc-ctrl
  ingress {
    description = "Wazuh agent enrollment from bc-ctrl"
    from_port   = 1515
    to_port     = 1515
    protocol    = "tcp"
    cidr_blocks = [local.vpc_cidr]
  }

  # Wazuh REST API from bc-ctrl
  ingress {
    description = "Wazuh API from bc-ctrl"
    from_port   = 55000
    to_port     = 55000
    protocol    = "tcp"
    cidr_blocks = [local.vpc_cidr]
  }

  # OpenSearch HTTP from bc-ctrl
  ingress {
    description = "OpenSearch HTTP from bc-ctrl"
    from_port   = 9200
    to_port     = 9200
    protocol    = "tcp"
    cidr_blocks = [local.vpc_cidr]
  }

  # Wazuh Dashboard HTTPS from bc-ctrl
  ingress {
    description = "Dashboard HTTPS from bc-ctrl"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [local.vpc_cidr]
  }

  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, { Name = "wazuh-ec2-sg" })
}

###############################################################
# IAM Role & Instance Profile
###############################################################

resource "aws_iam_role" "wazuh_ec2" {
  name = "wazuh-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = merge(local.common_tags, { Name = "wazuh-ec2-role" })
}

resource "aws_iam_role_policy_attachment" "wazuh_ec2_ssm" {
  role       = aws_iam_role.wazuh_ec2.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "wazuh_ec2_inline" {
  name = "wazuh-ec2-inline"
  role = aws_iam_role.wazuh_ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SecretsManagerWazuhMisp"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = [
          "arn:aws:secretsmanager:${local.region}:${data.aws_caller_identity.current.account_id}:secret:bc/wazuh/*",
          "arn:aws:secretsmanager:${local.region}:${data.aws_caller_identity.current.account_id}:secret:bc/misp*"
        ]
      },
      {
        # GAP-008: OpenSearch repository-s3 plugin snapshot operations.
        # DeleteObject: purge expired/deleted snapshot segments.
        # GetBucketLocation: required at repository-registration time to validate bucket region.
        # AbortMultipartUpload + ListBucketMultipartUploads: resume/abort incomplete
        #   multipart uploads for large shard files.
        # Scoped strictly to the snapshots bucket; no other buckets affected.
        # SSE on this bucket is AES256 (SSE-S3), so no KMS grant is required.
        Sid    = "S3WazuhSnapshotsReadWrite"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:DeleteObject",
          "s3:ListBucket",
          "s3:GetBucketLocation",
          "s3:AbortMultipartUpload",
          "s3:ListBucketMultipartUploads"
        ]
        Resource = [
          aws_s3_bucket.wazuh_snapshots.arn,
          "${aws_s3_bucket.wazuh_snapshots.arn}/*"
        ]
      },
      {
        Sid    = "S3LogBucketsReadOnly"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.cloudtrail_logs.arn,
          "${aws_s3_bucket.cloudtrail_logs.arn}/*",
          aws_s3_bucket.guardduty_logs.arn,
          "${aws_s3_bucket.guardduty_logs.arn}/*",
          aws_s3_bucket.vpcflow_logs.arn,
          "${aws_s3_bucket.vpcflow_logs.arn}/*",
          aws_s3_bucket.config_logs.arn,
          "${aws_s3_bucket.config_logs.arn}/*"
        ]
      },
      {
        # Required by the Wazuh vpcflow wodle (aws-s3 bucket type).
        # DescribeFlowLogs: enumerate flow-log delivery metadata (confirmed-missing action).
        # DescribeNetworkInterfaces: resolve ENI IDs to IP/subnet/instance metadata for alert enrichment.
        # DescribeNetworkInterfaceAttribute: resolve interface descriptions in some Wazuh versions.
        # ec2:Describe* actions do NOT support resource-level constraints — Resource="*" is mandatory.
        Sid    = "EC2DescribeFlowLogsForWazuhVPCFlow"
        Effect = "Allow"
        Action = [
          "ec2:DescribeFlowLogs",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeNetworkInterfaceAttribute"
        ]
        Resource = "*"
      },
      {
        Sid    = "KMSWazuhEBS"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:GenerateDataKeyWithoutPlaintext",
          "kms:DescribeKey",
          "kms:CreateGrant"
        ]
        Resource = [aws_kms_key.wazuh_ec2.arn]
      },
      {
        # F-10: EKS control-plane AUDIT log ingestion via the Wazuh
        # CloudWatch Logs wodle (service type="cloudwatchlogs" in
        # phase3-install-wazuh.sh, rules bc-k8s-audit.xml 100401-100405).
        # Read-only on the EKS audit log group only. Applied live
        # 2026-06-10 as the out-of-band "wazuh-eks-audit-read" policy;
        # captured here so a cold-start rebuild recreates it.
        Sid    = "CloudWatchLogsEKSAuditRead"
        Effect = "Allow"
        Action = [
          "logs:GetLogEvents",
          "logs:FilterLogEvents",
          "logs:DescribeLogStreams",
          "logs:DescribeLogGroups"
        ]
        Resource = "arn:aws:logs:${local.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/eks/bc-uatms-prd-eks/cluster:*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "wazuh_ec2" {
  name = "wazuh-ec2-profile"
  role = aws_iam_role.wazuh_ec2.name

  tags = merge(local.common_tags, { Name = "wazuh-ec2-profile" })
}

###############################################################
# KMS CMK — EBS encryption for all Wazuh EC2 volumes
###############################################################

resource "aws_kms_key" "wazuh_ec2" {
  description             = "CMK for Wazuh EC2 EBS volumes"
  deletion_window_in_days = 30
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
        Sid    = "WazuhInstanceRoleUse"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.wazuh_ec2.arn
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:GenerateDataKeyWithoutPlaintext",
          "kms:DescribeKey",
          "kms:CreateGrant"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(local.common_tags, { Name = "wazuh-ec2-cmk" })
}

resource "aws_kms_alias" "wazuh_ec2" {
  name          = "alias/wazuh-ec2"
  target_key_id = aws_kms_key.wazuh_ec2.key_id
}

###############################################################
# S3 Bucket — Wazuh install scripts and rule XML files
###############################################################

resource "aws_s3_bucket" "wazuh_snapshots" {
  bucket        = local.wazuh_bucket
  force_destroy = true

  tags = merge(local.common_tags, { Name = local.wazuh_bucket })
}

resource "aws_s3_bucket_public_access_block" "wazuh_snapshots" {
  bucket                  = aws_s3_bucket.wazuh_snapshots.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

###############################################################
# Install script — uploaded to S3, pulled by user_data on boot
###############################################################

resource "aws_s3_object" "wazuh_install_script" {
  bucket                 = aws_s3_bucket.wazuh_snapshots.id
  key                    = "scripts/phase3-install-wazuh.sh"
  source                 = "${path.module}/../../../scripts/phase3-install-wazuh.sh"
  source_hash            = filemd5("${path.module}/../../../scripts/phase3-install-wazuh.sh")
  server_side_encryption = "AES256"

  force_destroy = true

  lifecycle {
    ignore_changes = [object_lock_mode, object_lock_retain_until_date, object_lock_legal_hold_status]
  }
}

# Custom Wazuh rule XML files — synced to /var/ossec/etc/rules/ on the manager
# by phase3-install-wazuh.sh. Adding a new XML file under new-infra/wazuh/rules/
# automatically uploads it; no Terraform edit needed.
resource "aws_s3_object" "wazuh_rules" {
  for_each               = fileset("${path.module}/../../../wazuh/rules", "*.xml")
  bucket                 = aws_s3_bucket.wazuh_snapshots.id
  key                    = "rules/${each.value}"
  source                 = "${path.module}/../../../wazuh/rules/${each.value}"
  source_hash            = filemd5("${path.module}/../../../wazuh/rules/${each.value}")
  server_side_encryption = "AES256"
  force_destroy          = true

  lifecycle {
    ignore_changes = [object_lock_mode, object_lock_retain_until_date, object_lock_legal_hold_status]
  }
}

###############################################################
# Wazuh all-in-one instance
###############################################################

resource "aws_instance" "wazuh" {
  ami                         = data.aws_ami.al2023.id # Amazon Linux 2023 x86_64
  instance_type               = "t3.xlarge"
  subnet_id                   = module.vpc.private_subnet_ids[0]
  user_data_replace_on_change = true

  vpc_security_group_ids = [aws_security_group.wazuh_ec2.id]
  iam_instance_profile   = aws_iam_instance_profile.wazuh_ec2.name

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_size           = 60
    volume_type           = "gp3"
    encrypted             = true
    kms_key_id            = aws_kms_key.wazuh_ec2.arn
    delete_on_termination = true
  }

  user_data = <<-EOF
    #!/bin/bash
    set -euo pipefail
    exec > >(tee /var/log/wazuh-install.log | logger -t wazuh-install) 2>&1

    # Script hash (forces instance replacement when script changes): ${filemd5("${path.module}/../../../scripts/phase3-install-wazuh.sh")}
    # Rules hash (forces replacement when any rule XML changes): ${md5(join(",", [for f in fileset("${path.module}/../../../wazuh/rules", "*.xml") : filemd5("${path.module}/../../../wazuh/rules/${f}")]))}

    dnf update -y
    dnf install -y unzip jq

    # Install AWS CLI v2
    curl -fsSL https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o /tmp/awscliv2.zip
    unzip -q /tmp/awscliv2.zip -d /tmp/awscliv2-extract
    /tmp/awscliv2-extract/aws/install
    rm -rf /tmp/awscliv2.zip /tmp/awscliv2-extract

    # Download and run install script
    aws s3 cp s3://${aws_s3_object.wazuh_install_script.bucket}/${aws_s3_object.wazuh_install_script.key} \
      /tmp/phase3-install-wazuh.sh --region ${local.region}
    chmod +x /tmp/phase3-install-wazuh.sh

    HOST_ROLE=all_in_one \
    WAZUH_S3_BUCKET=${local.wazuh_bucket} \
      bash /tmp/phase3-install-wazuh.sh
  EOF

  tags = merge(local.common_tags, { Name = "wazuh-ctrl" })

  depends_on = [
    aws_s3_object.wazuh_install_script,
    aws_s3_object.wazuh_rules,
  ]

  lifecycle {
    ignore_changes = [ami]
  }
}

resource "aws_ebs_volume" "wazuh_data" {
  availability_zone = local.azs[0] # eu-west-1a — same AZ as private_subnet_ids[0]
  size              = 200
  type              = "gp3"
  iops              = 6000
  throughput        = 250
  encrypted         = true
  kms_key_id        = aws_kms_key.wazuh_ec2.arn

  tags = merge(local.common_tags, { Name = "wazuh-data" })
}

resource "aws_volume_attachment" "wazuh_data" {
  device_name = "/dev/xvdf"
  volume_id   = aws_ebs_volume.wazuh_data.id
  instance_id = aws_instance.wazuh.id
}

###############################################################
# Route53 — private A records in bc-ctrl.internal
# All 3 DNS names point to the single all-in-one instance
###############################################################

resource "aws_route53_record" "wazuh_manager" {
  zone_id = aws_route53_zone.bc_ctrl_internal.zone_id
  name    = "wazuh-manager.bc-ctrl.internal"
  type    = "A"
  ttl     = 60
  records = [aws_instance.wazuh.private_ip]
}

resource "aws_route53_record" "wazuh_indexer" {
  zone_id = aws_route53_zone.bc_ctrl_internal.zone_id
  name    = "wazuh-indexer.bc-ctrl.internal"
  type    = "A"
  ttl     = 60
  records = [aws_instance.wazuh.private_ip]
}

resource "aws_route53_record" "wazuh_dashboard" {
  zone_id = aws_route53_zone.bc_ctrl_internal.zone_id
  name    = "wazuh-dashboard.bc-ctrl.internal"
  type    = "A"
  ttl     = 60
  records = [aws_instance.wazuh.private_ip]
}

###############################################################
# Outputs
###############################################################

output "wazuh_private_ip" {
  description = "Private IP of the Wazuh all-in-one EC2 instance"
  value       = aws_instance.wazuh.private_ip
}
