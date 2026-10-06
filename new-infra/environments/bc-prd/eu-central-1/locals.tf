locals {
  region        = "eu-west-1"
  company       = "big-chemistry"
  env           = "prd"
  platform_name = "bc-uatms"

  vpc_cidr = "10.30.0.0/16"
  azs      = ["eu-west-1a", "eu-west-1b"]

  common_tags = {
    Project     = "UATMS"
    Environment = local.env
    Customer    = "Big Chemistry"
    IACTool     = "Terraform"
  }
}
