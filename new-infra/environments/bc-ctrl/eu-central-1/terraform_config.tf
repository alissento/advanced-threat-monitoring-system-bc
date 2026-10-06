terraform {
  required_version = ">= 1.5.7"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.23"
    }
  }

  backend "s3" {
    bucket = "bc-uatms-terraform-state-929026881368"
    key    = "v8/environments/bc-ctrl/terraform.tfstate"
    region = "eu-west-1"
  }
}

provider "aws" {
  region = local.region
}

data "aws_caller_identity" "current" {}
