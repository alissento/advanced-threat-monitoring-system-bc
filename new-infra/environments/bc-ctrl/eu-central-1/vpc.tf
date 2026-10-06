module "vpc" {
  source = "../../../modules/network/vpc"

  vpc_name           = "${local.platform_name}-${local.env}-vpc"
  cidr_block         = local.vpc_cidr
  availability_zones = local.azs

  public_subnet_cidrs  = [cidrsubnet(local.vpc_cidr, 8, 0), cidrsubnet(local.vpc_cidr, 8, 1)]   # 10.0.0.0/24, 10.0.1.0/24
  private_subnet_cidrs = [cidrsubnet(local.vpc_cidr, 8, 10), cidrsubnet(local.vpc_cidr, 8, 11)] # 10.0.10.0/24, 10.0.11.0/24

  enable_nat_gateway = false # Using fck-nat

  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = local.common_tags
}

# fck-nat (Shared for both VPCs)
resource "aws_security_group" "fck_nat" {
  name        = "fck-nat-sg"
  description = "Allow all from internal CIDRs"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = local.common_tags
}

resource "aws_instance" "fck_nat" {
  ami                         = data.aws_ami.fck_nat.id # fck-nat ARM64 (region-agnostic lookup)
  instance_type               = "t4g.nano"
  subnet_id                   = module.vpc.public_subnet_ids[0]
  associate_public_ip_address = true
  source_dest_check           = false
  user_data_replace_on_change = true
  vpc_security_group_ids      = [aws_security_group.fck_nat.id]
  iam_instance_profile        = aws_iam_instance_profile.fck_nat.name

  # MASQUERADE all RFC1918 traffic destined for internet (covers bc-ctrl nodes + bc-prd peering traffic)
  user_data = <<-EOF
              #!/bin/bash
              echo 1 > /proc/sys/net/ipv4/ip_forward
              iptables -t nat -A POSTROUTING -s 10.0.0.0/8 ! -d 10.0.0.0/8 -o eth0 -j MASQUERADE
              EOF

  tags = merge(local.common_tags, { Name = "fck-nat-shared" })

  lifecycle {
    ignore_changes = [ami]
  }
}

resource "aws_iam_role" "fck_nat" {
  name = "fck-nat-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "fck_nat_ssm" {
  role       = aws_iam_role.fck_nat.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "fck_nat" {
  name = "fck-nat-profile"
  role = aws_iam_role.fck_nat.name
}

# Routes in bc-ctrl private RTs to use fck-nat for internet (one per AZ)
resource "aws_route" "private_nat" {
  count                  = length(module.vpc.private_route_table_ids)
  route_table_id         = module.vpc.private_route_table_ids[count.index]
  destination_cidr_block = "0.0.0.0/0"
  network_interface_id   = aws_instance.fck_nat.primary_network_interface_id
}

###############################################################
# VPC Flow Logs — bc-ctrl
###############################################################

resource "aws_s3_bucket" "vpcflow_logs" {
  bucket        = local.vpcflow_bucket
  force_destroy = true

  tags = merge(local.common_tags, { Name = local.vpcflow_bucket })
}

resource "aws_s3_bucket_public_access_block" "vpcflow_logs" {
  bucket                  = aws_s3_bucket.vpcflow_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "vpcflow_logs" {
  bucket = aws_s3_bucket.vpcflow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSLogDeliveryWrite"
        Effect    = "Allow"
        Principal = { Service = "delivery.logs.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.vpcflow_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      },
      {
        Sid       = "AWSLogDeliveryAclCheck"
        Effect    = "Allow"
        Principal = { Service = "delivery.logs.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.vpcflow_logs.arn
      }
    ]
  })
}

resource "aws_flow_log" "bc_ctrl" {
  vpc_id               = module.vpc.vpc_id
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = aws_s3_bucket.vpcflow_logs.arn

  tags = merge(local.common_tags, { Name = "bc-ctrl-vpc-flow-log" })

  depends_on = [aws_s3_bucket_policy.vpcflow_logs]
}

output "vpc_id" {
  value = module.vpc.vpc_id
}

output "public_route_table_ids" {
  value = module.vpc.public_route_table_ids
}

output "private_route_table_ids" {
  value = module.vpc.private_route_table_ids
}
