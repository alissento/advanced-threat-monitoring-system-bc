# ---------------------------------------------------------------------------
# EFS File System for NOMAD Oasis
#
# One EFS file system shared across bc-prd private subnets.
# EFS CSI driver provisions per-PVC access points under /nomad (basePath),
# so each PersistentVolumeClaim gets its own isolated directory tree while
# sharing the same underlying file system — avoids the 1-PVC-per-FS limit of
# static provisioning.
#
# Lifecycle: files not accessed for 30 days are moved to IA storage
# ($0.025/GB vs $0.30/GB standard) to keep NOMAD archive costs low.
# ---------------------------------------------------------------------------

resource "aws_efs_file_system" "nomad_oasis" {
  creation_token   = "${local.platform_name}-${local.env}-nomad-oasis"
  encrypted        = true
  kms_key_id       = module.eks.kms_key_arn
  performance_mode = "generalPurpose"
  throughput_mode  = "bursting"

  lifecycle_policy {
    transition_to_ia = "AFTER_30_DAYS"
  }

  tags = merge(local.common_tags, {
    Name = "${local.platform_name}-${local.env}-nomad-oasis"
  })
}

# ---------------------------------------------------------------------------
# Security group — EFS mount targets
# Allow NFS (TCP 2049) from EKS node SG only. No wider access.
# ---------------------------------------------------------------------------
resource "aws_security_group" "nomad_efs" {
  name        = "${local.platform_name}-${local.env}-nomad-efs-sg"
  description = "EFS mount access for NOMAD Oasis -- EKS nodes only"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description     = "NFS from EKS node SG"
    from_port       = 2049
    to_port         = 2049
    protocol        = "tcp"
    security_groups = [module.eks.node_security_group_id]
  }

  egress {
    description = "Allow all egress (EFS kernel driver initiates connections)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${local.platform_name}-${local.env}-nomad-efs-sg"
  })
}

# ---------------------------------------------------------------------------
# Mount targets — one per private subnet (covers both AZs)
#
# count instead of for_each: on cold-start, module.vpc.private_subnet_ids is
# apply-time-unknown (subnets are being created in the same plan), so toset()
# cannot produce plan-time-known keys — Terraform errors. count only needs the
# *number* to be known at plan time; element values (subnet_id) can be
# apply-time-unknown.
#
# bc-prd is permanently 2-AZ (eu-west-1a + eu-west-1b), so count = 2 is
# safe to hard-code. If AZs are ever expanded, increment this value AND run
# `terraform state mv` for existing mount targets before applying to avoid
# destroying live mount targets on warm-state deployments:
#   terraform state mv \
#     'aws_efs_mount_target.nomad_oasis["subnet-<old-id>"]' \
#     'aws_efs_mount_target.nomad_oasis[0]'
# ---------------------------------------------------------------------------
resource "aws_efs_mount_target" "nomad_oasis" {
  count = 2 # one per bc-prd private subnet — eu-west-1a and eu-west-1b

  file_system_id  = aws_efs_file_system.nomad_oasis.id
  subnet_id       = module.vpc.private_subnet_ids[count.index]
  security_groups = [aws_security_group.nomad_efs.id]
}

# ---------------------------------------------------------------------------
# StorageClass — efs-nomad-sc
#
# Security-stack-engineer's NOMAD Helm values must reference this exact name.
# provisioner: efs.csi.aws.com (installed via aws-efs-csi-driver addon)
# provisioningMode: efs-ap — driver creates an EFS access point per PVC,
#   rooted at basePath=/nomad/<pvc-uid>. gidRangeStart/End give each volume
#   a unique GID in the 1000–2000 range, preventing cross-volume access.
# ---------------------------------------------------------------------------
resource "kubernetes_storage_class" "efs_nomad" {
  metadata {
    name = "efs-nomad-sc"
    annotations = {
      "storageclass.kubernetes.io/is-default-class" = "false"
    }
  }

  storage_provisioner    = "efs.csi.aws.com"
  reclaim_policy         = "Retain"
  volume_binding_mode    = "Immediate"
  allow_volume_expansion = false

  parameters = {
    provisioningMode = "efs-ap"
    fileSystemId     = aws_efs_file_system.nomad_oasis.id
    directoryPerms   = "0755"
    gidRangeStart    = "1000"
    gidRangeEnd      = "2000"
    basePath         = "/nomad"
  }

  depends_on = [
    module.eks,
    aws_efs_mount_target.nomad_oasis,
  ]
}

# ---------------------------------------------------------------------------
# StorageClass — gp3
#
# nomad-values.yaml references storageClass: gp3 for MongoDB, PostgreSQL, and
# Elasticsearch PVCs.  No such SC ships with EKS by default (only gp2 exists
# out of the box).  This resource creates it so PVC binding succeeds.
#
# WaitForFirstConsumer lets the scheduler pick a node before the EBS volume is
# provisioned, avoiding cross-AZ binding traps when nodes span eu-west-1a
# and eu-west-1b.
#
# Import note: if this SC was already applied live via kubectl during incident
# response, adopt it with:
#   terraform import kubernetes_storage_class.gp3 gp3
# The spec is intentionally matched exactly so TF detects no drift.
# ---------------------------------------------------------------------------
resource "kubernetes_storage_class" "gp3" {
  metadata {
    name = "gp3"
    annotations = {
      "storageclass.kubernetes.io/is-default-class" = "false"
    }
  }

  storage_provisioner    = "ebs.csi.aws.com"
  reclaim_policy         = "Delete"
  volume_binding_mode    = "WaitForFirstConsumer"
  allow_volume_expansion = true

  parameters = {
    type      = "gp3"
    encrypted = "true"
  }

  depends_on = [
    module.eks,
    aws_iam_role_policy_attachment.ebs_csi,
  ]
}
