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
