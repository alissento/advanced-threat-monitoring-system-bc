locals {
  region        = "eu-west-1"
  company       = "big-chemistry"
  env           = "ctrl"
  platform_name = "bc-uatms"

  vpc_cidr     = "10.0.0.0/16"
  prd_vpc_cidr = "10.30.0.0/16"               # bc-prd — Wazuh agents connect via VPC peering
  azs          = ["eu-west-1a", "eu-west-1b"] # EKS requires 2+ AZs

  common_tags = {
    Project     = "UATMS"
    Environment = local.env
    Customer    = "Big Chemistry"
    IACTool     = "Terraform"
  }

  # All S3 bucket names are account-suffixed for global uniqueness and cold-start reproducibility.
  # Older accounts may still own the unsuffixed names — never use bare names.
  wazuh_bucket      = "bc-uatms-wazuh-snapshots-${data.aws_caller_identity.current.account_id}"
  vpcflow_bucket    = "bc-vpcflow-logs-${data.aws_caller_identity.current.account_id}"
  cloudtrail_bucket = "bc-cloudtrail-logs-${data.aws_caller_identity.current.account_id}"
  guardduty_bucket  = "bc-guardduty-logs-${data.aws_caller_identity.current.account_id}"
  config_bucket     = "bc-config-logs-${data.aws_caller_identity.current.account_id}"
}
