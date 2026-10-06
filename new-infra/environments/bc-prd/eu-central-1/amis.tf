# Region-agnostic fck-nat AMI lookup (replaces hardcoded eu-central-1 AMI ID).
# Consumer instance carries `lifecycle { ignore_changes = [ami] }`.

data "aws_ami" "fck_nat" {
  most_recent = true
  owners      = ["568608671756"] # fck-nat publisher

  filter {
    name   = "name"
    values = ["fck-nat-al2023-*-arm64-ebs"]
  }

  filter {
    name   = "architecture"
    values = ["arm64"]
  }
}
