# ALB công khai: chỉ nhận 443 từ Internet (N03), egress mặc định (N04).
resource "aws_security_group" "alb" {
  name        = "${var.name_prefix}-alb"
  description = "ALB cong khai, chi mo 443"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS tu Internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Egress mac dinh"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name_prefix}-alb" }
}

# App: chỉ nhận lưu lượng từ ALB, không mở ra Internet.
resource "aws_security_group" "app" {
  name        = "${var.name_prefix}-app"
  description = "App chi nhan tu ALB"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "App port tu ALB"
    from_port       = var.app_port
    to_port         = var.app_port
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "${var.name_prefix}-app" }
}
