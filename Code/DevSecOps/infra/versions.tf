terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region

  # Không gọi AWS khi chỉ validate; apply thật mới cần credential.
  default_tags {
    tags = {
      project = "devsecops-21"
      owner   = var.owner_tag
    }
  }
}
