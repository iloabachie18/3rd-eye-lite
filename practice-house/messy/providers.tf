# Settings for the 3RD EYE "messy" practice house.
# Everything here is built in the 3rdeye-messy account ONLY.

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
  profile = "messy" # the AWS CLI profile we created earlier

  # Every resource gets these labels automatically,
  # so we always know it's a planted 3RD EYE test item.
  default_tags {
    tags = {
      Project   = "3rd-eye"
      House     = "messy"
      ManagedBy = "terraform"
    }
  }
}