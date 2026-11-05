variable "region" {
  type    = string
  default = "ap-southeast-1"
}

variable "name_prefix" {
  type    = string
  default = "devsecops"
}

variable "owner_tag" {
  type    = string
  default = "team21"
}

variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "app_port" {
  type    = number
  default = 8000
}

variable "db_username" {
  type    = string
  default = "appuser"
}

# Mật khẩu lấy từ biến, không ghi trong mã.
variable "db_password" {
  type      = string
  sensitive = true
}

variable "instance_type" {
  type    = string
  default = "t3.micro"
}

# Image đã được job release ký, bắt buộc ghi theo digest (không dùng tag).
variable "app_image" {
  type        = string
  description = "Image ứng dụng theo digest, ví dụ ghcr.io/tranhuultai/devsecops@sha256:<64 ký tự hex>"

  validation {
    condition     = can(regex("^ghcr\\.io/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$", var.app_image))
    error_message = "app_image phải là image trên GHCR ghi theo digest @sha256:..., không dùng tag."
  }
}

# Chỉ chấp nhận chữ ký do workflow của chính repo này tạo (OIDC của GitHub Actions).
variable "signer_identity_regexp" {
  type    = string
  default = "^https://github.com/tranhuultai/012012303904_21_DevSecOps/.github/workflows/.+"
}

# Chứng chỉ ACM cho tên miền gắn với ALB; ALB chỉ phục vụ HTTPS.
variable "certificate_arn" {
  type        = string
  description = "ARN chứng chỉ ACM, ví dụ arn:aws:acm:ap-southeast-1:<account>:certificate/<id>"
}
