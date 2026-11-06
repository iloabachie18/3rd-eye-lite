# Settings for the 3RD EYE "clean" practice house.
# Everything here is built in the 3rdeye-clean account ONLY.

terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region  = "us-east-1"
  profile = "clean" # the AWS CLI profile for the clean account

  default_tags {
    tags = {
      Project   = "3rd-eye"
      House     = "clean"
      ManagedBy = "terraform"
    }
  }
}