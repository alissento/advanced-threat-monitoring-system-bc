#--------------------------------------------------------------
# ECR — Container image repositories
#
# The wazuh-agent ECR repository must live in bc-ctrl state so
# it is created during Job 1 (ctrl-plane, full terraform apply)
# before Job 2 (production-plane) runs the docker build+push
# step.  ECR is an account/region-level resource, not VPC-scoped,
# so ownership in bc-ctrl state does not affect bc-prd node pulls.
#
# Repository policy: none required.  GitHubActionsDeployRole /
# github-runner-role (AdministratorAccess) handles pushes.
# bc-prd node roles get AmazonEC2ContainerRegistryReadOnly
# attached automatically by terraform-aws-modules/eks/aws ~> 20.x
# (wired unconditionally in the managed node group IAM role).
# Cross-account access is not needed (same account: 929026881368).
#--------------------------------------------------------------

###############################################################
# wazuh-agent image repository
###############################################################

resource "aws_ecr_repository" "wazuh_agent" {
  name                 = "wazuh-agent"
  image_tag_mutability = "MUTABLE" # pipeline re-pushes tag 4.14.4 on each build

  image_scanning_configuration {
    scan_on_push = true
  }

  # Allows teardown/migration without manually draining images first.
  # Consistent with force_destroy = true used on all S3 buckets in this env.
  force_delete = true

  tags = merge(local.common_tags, { Name = "wazuh-agent" })
}

resource "aws_ecr_lifecycle_policy" "wazuh_agent" {
  repository = aws_ecr_repository.wazuh_agent.name

  policy = jsonencode({
    rules = [
      {
        # Remove untagged (intermediate/failed) images after 1 day
        rulePriority = 1
        description  = "Expire untagged images after 1 day"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 1
        }
        action = { type = "expire" }
      },
      {
        # Keep only the 5 most recent tagged images to cap storage cost.
        # tagPatternList = ["*"] matches all tag strings (ECR supports wildcard patterns).
        rulePriority = 2
        description  = "Keep last 5 tagged images"
        selection = {
          tagStatus      = "tagged"
          tagPatternList = ["*"]
          countType      = "imageCountMoreThan"
          countNumber    = 5
        }
        action = { type = "expire" }
      }
    ]
  })
}
