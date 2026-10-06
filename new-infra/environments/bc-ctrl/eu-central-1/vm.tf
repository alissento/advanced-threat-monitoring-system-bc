resource "aws_security_group" "github_runner" {
  name        = "github-runner-sg"
  description = "Allow all outbound for GH Runner"
  vpc_id      = module.vpc.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.common_tags
}

resource "aws_instance" "github_runner" {
  ami                         = data.aws_ami.al2023.id # Amazon Linux 2023 x86_64
  instance_type               = "t3.small"
  subnet_id                   = module.vpc.public_subnet_ids[0]
  associate_public_ip_address = true
  user_data_replace_on_change = true

  vpc_security_group_ids = [aws_security_group.github_runner.id]
  iam_instance_profile   = aws_iam_instance_profile.github_runner.name

  user_data = <<-EOT
              #!/bin/bash
              yum update -y
              yum install -y docker git jq libicu nodejs
              systemctl enable --now docker
              usermod -aG docker ec2-user

              # GitHub Runner Setup
              mkdir -p /home/ec2-user/actions-runner && cd /home/ec2-user/actions-runner
              curl -o actions-runner-linux-x64-2.316.1.tar.gz -L https://github.com/actions/runner/releases/download/v2.316.1/actions-runner-linux-x64-2.316.1.tar.gz
              tar xzf ./actions-runner-linux-x64-2.316.1.tar.gz
              chown -R ec2-user:ec2-user /home/ec2-user/actions-runner

              # Install dependencies
              ./bin/installdependencies.sh

              # Install Terraform
              yum install -y yum-utils
              yum-config-manager --add-repo https://rpm.releases.hashicorp.com/AmazonLinux/hashicorp.repo
              yum -y install terraform

              # Install kubectl
              curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
              install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

              # Install Helm
              curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

              # Get registration token using PAT
              PAT=$(aws secretsmanager get-secret-value --secret-id bc/github/runnerpat --query SecretString --output text --region ${local.region})
              TOKEN=$(curl -X POST -H "Authorization: token $PAT" -H "Accept: application/vnd.github.v3+json" https://api.github.com/repos/alissento/advanced-threat-monitoring-system-bc/actions/runners/registration-token | jq -r .token)

              sudo -u ec2-user ./config.sh --url https://github.com/alissento/advanced-threat-monitoring-system-bc --token $TOKEN --name $(hostname) --unattended --replace
              ./svc.sh install
              ./svc.sh start
              EOT

  tags = merge(local.common_tags, { Name = "github-runner-ctrl" })

  lifecycle {
    ignore_changes = [ami]
  }
}

resource "aws_iam_role" "github_runner" {
  name = "github-runner-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "runner_admin" {
  role       = aws_iam_role.github_runner.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_iam_instance_profile" "github_runner" {
  name = "github-runner-profile"
  role = aws_iam_role.github_runner.name
}

###############################################################
# MISP — Malware Information Sharing Platform
#
# Co-located MySQL (localhost-only). Queried by:
#   - Wazuh Manager in bc-ctrl via HTTPS (port 443)
#   - Suricata misp-rule-sync sidecar in bc-prd via HTTPS (port 443)
#   - Zeek misp-intel-sync sidecar in bc-prd via HTTPS (port 443)
# Reachable from bc-prd via VPC peering.
###############################################################

resource "aws_security_group" "misp_ec2" {
  name        = "misp-ec2-sg"
  description = "MISP instance - HTTPS from bc-ctrl only"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description = "MISP HTTPS from bc-ctrl"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [local.vpc_cidr]
  }

  ingress {
    description = "MISP HTTPS from bc-prd (Suricata/Zeek MISP sync sidecars)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [local.prd_vpc_cidr]
  }

  ingress {
    description = "HTTP redirect from bc-ctrl"
    from_port   = 80
    to_port     = 80
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

  tags = merge(local.common_tags, { Name = "misp-ec2-sg" })
}

resource "aws_iam_role" "misp_ec2" {
  name = "misp-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  tags = merge(local.common_tags, { Name = "misp-ec2-role" })
}

resource "aws_iam_role_policy_attachment" "misp_ec2_ssm" {
  role       = aws_iam_role.misp_ec2.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "misp_ec2_inline" {
  name = "misp-ec2-inline"
  role = aws_iam_role.misp_ec2.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SecretsManagerMisp"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
          "secretsmanager:PutSecretValue"
        ]
        Resource = [
          "arn:aws:secretsmanager:${local.region}:${data.aws_caller_identity.current.account_id}:secret:bc/misp*",
          "arn:aws:secretsmanager:${local.region}:${data.aws_caller_identity.current.account_id}:secret:bc/suricata/misp*",
          "arn:aws:secretsmanager:${local.region}:${data.aws_caller_identity.current.account_id}:secret:bc/zeek/misp*"
        ]
      },
      {
        Sid      = "S3ScriptDownload"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = ["${aws_s3_bucket.wazuh_snapshots.arn}/scripts/*"]
      },
      {
        Sid    = "KMSMispEBS"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:GenerateDataKeyWithoutPlaintext",
          "kms:DescribeKey",
          "kms:CreateGrant"
        ]
        Resource = [aws_kms_key.misp_ec2.arn]
      }
    ]
  })
}

resource "aws_iam_instance_profile" "misp_ec2" {
  name = "misp-ec2-profile"
  role = aws_iam_role.misp_ec2.name

  tags = merge(local.common_tags, { Name = "misp-ec2-profile" })
}

resource "aws_kms_key" "misp_ec2" {
  description             = "CMK for MISP EC2 EBS volumes"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "RootFullAccess"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "MispInstanceRoleUse"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.misp_ec2.arn }
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

  tags = merge(local.common_tags, { Name = "misp-ec2-cmk" })
}

resource "aws_kms_alias" "misp_ec2" {
  name          = "alias/misp-ec2"
  target_key_id = aws_kms_key.misp_ec2.key_id
}

resource "aws_s3_object" "misp_install_script" {
  bucket                 = aws_s3_bucket.wazuh_snapshots.id
  key                    = "scripts/phase4-install-misp.sh"
  source                 = "${path.module}/../../../scripts/phase4-install-misp.sh"
  source_hash            = filemd5("${path.module}/../../../scripts/phase4-install-misp.sh")
  server_side_encryption = "AES256"

  force_destroy = true

  lifecycle {
    ignore_changes = [object_lock_mode, object_lock_retain_until_date, object_lock_legal_hold_status]
  }
}

resource "aws_instance" "misp" {
  ami                         = data.aws_ami.al2023.id # Amazon Linux 2023 x86_64
  instance_type               = "t3.large"
  subnet_id                   = module.vpc.private_subnet_ids[0]
  user_data_replace_on_change = true

  vpc_security_group_ids = [aws_security_group.misp_ec2.id]
  iam_instance_profile   = aws_iam_instance_profile.misp_ec2.name

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_size           = 30
    volume_type           = "gp3"
    encrypted             = true
    kms_key_id            = aws_kms_key.misp_ec2.arn
    delete_on_termination = true
  }

  user_data = <<-EOF
    #!/bin/bash
    set -euo pipefail
    exec > >(tee /var/log/misp-install.log | logger -t misp-install) 2>&1

    dnf update -y
    dnf install -y unzip jq

    # Install AWS CLI v2
    curl -fsSL https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o /tmp/awscliv2.zip
    unzip -q /tmp/awscliv2.zip -d /tmp/awscliv2-extract
    /tmp/awscliv2-extract/aws/install
    rm -rf /tmp/awscliv2.zip /tmp/awscliv2-extract

    # Download and run install script
    aws s3 cp s3://${aws_s3_object.misp_install_script.bucket}/${aws_s3_object.misp_install_script.key} \
      /tmp/phase4-install-misp.sh --region ${local.region}
    # Normalize line endings: a CRLF-tainted upload (e.g. a Windows local
    # terraform apply) would otherwise fail at the script's `set -o pipefail`
    # with "invalid option name". This makes the bootstrap CRLF-immune.
    sed -i 's/\r$//' /tmp/phase4-install-misp.sh
    chmod +x /tmp/phase4-install-misp.sh
    bash /tmp/phase4-install-misp.sh
  EOF

  tags = merge(local.common_tags, { Name = "misp-ctrl" })

  depends_on = [aws_s3_object.misp_install_script]

  lifecycle {
    ignore_changes = [ami]
  }
}

resource "aws_ebs_volume" "misp_data" {
  availability_zone = local.azs[0]
  size              = 60
  type              = "gp3"
  encrypted         = true
  kms_key_id        = aws_kms_key.misp_ec2.arn

  tags = merge(local.common_tags, { Name = "misp-data" })
}

resource "aws_volume_attachment" "misp_data" {
  device_name = "/dev/xvdf"
  volume_id   = aws_ebs_volume.misp_data.id
  instance_id = aws_instance.misp.id
}

resource "aws_route53_record" "misp" {
  zone_id = aws_route53_zone.bc_ctrl_internal.zone_id
  name    = "misp.bc-ctrl.internal"
  type    = "A"
  ttl     = 60
  records = [aws_instance.misp.private_ip]
}

output "misp_private_ip" {
  description = "Private IP of the MISP EC2 instance"
  value       = aws_instance.misp.private_ip
}
