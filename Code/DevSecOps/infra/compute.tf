# Máy chạy ứng dụng: một EC2 đứng sau ALB.
# Khi khởi động, EC2 chạy scripts/ec2_bootstrap.sh: kiểm chữ ký image bằng cosign
# (đúng danh tính workflow của repo) rồi mới chạy container, giống job deploy-smoke.

# Ubuntu 24.04 chính hãng của Canonical, cùng hệ điều hành với runner ubuntu-24.04
# dùng để chạy thử script khởi động trong workflow iac-validate.
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_iam_instance_profile" "app" {
  name = "${var.name_prefix}-app"
  role = aws_iam_role.app.name
}

resource "aws_instance" "app" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public[0].id
  vpc_security_group_ids = [aws_security_group.app.id]
  iam_instance_profile   = aws_iam_instance_profile.app.name
  monitoring             = true
  ebs_optimized          = true

  # Địa chỉ công khai chỉ để EC2 tải image và gọi Sigstore, không cần NAT Gateway.
  # Security group app không mở cổng nào ra Internet, chỉ nhận từ ALB.
  associate_public_ip_address = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    encrypted   = true
    volume_type = "gp3"
    volume_size = 8
  }

  user_data_replace_on_change = true
  user_data                   = <<-EOT
    #!/bin/bash
    export APP_IMAGE='${var.app_image}'
    export SIGNER_IDENTITY_REGEXP='${var.signer_identity_regexp}'
    export APP_PORT='${var.app_port}'
    ${file("${path.module}/scripts/ec2_bootstrap.sh")}
  EOT

  tags = { Name = "${var.name_prefix}-app" }
}

resource "aws_lb" "app" {
  name                       = "${var.name_prefix}-alb"
  load_balancer_type         = "application"
  internal                   = false
  security_groups            = [aws_security_group.alb.id]
  subnets                    = aws_subnet.public[*].id
  drop_invalid_header_fields = true

  # Môi trường thử: phải xóa được bằng terraform destroy.
  enable_deletion_protection = false

  tags = { Name = "${var.name_prefix}-alb" }
}

resource "aws_lb_target_group" "app" {
  name     = "${var.name_prefix}-app"
  port     = var.app_port
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id

  health_check {
    path                = "/health"
    matcher             = "200"
    interval            = 15
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_target_group_attachment" "app" {
  target_group_arn = aws_lb_target_group.app.arn
  target_id        = aws_instance.app.id
  port             = var.app_port
}

# Chỉ có HTTPS (security group ALB chỉ mở 443); chứng chỉ ACM gắn với tên miền của nhóm.
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.app.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}
