# Kiểm cấu hình hạ tầng bằng provider giả lập (mock_provider, Terraform >= 1.7):
# không cần tài khoản AWS, không tạo tài nguyên thật, không tốn phí.
# Mỗi run dựng toàn bộ cấu hình trong bộ nhớ rồi kiểm các thuộc tính bảo mật đã thiết kế.
# Chạy: terraform init -backend=false && terraform test

mock_provider "aws" {
  mock_data "aws_availability_zones" {
    defaults = {
      names = ["ap-southeast-1a", "ap-southeast-1b"]
    }
  }

  mock_data "aws_ami" {
    defaults = {
      id = "ami-0123456789abcdef0"
    }
  }

  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }

  # Provider kiểm định dạng ARN của listener, nên ARN giả phải đúng cấu trúc.
  mock_resource "aws_lb" {
    defaults = {
      arn = "arn:aws:elasticloadbalancing:ap-southeast-1:123456789012:loadbalancer/app/devsecops-alb/0123456789abcdef"
    }
  }

  mock_resource "aws_lb_target_group" {
    defaults = {
      arn = "arn:aws:elasticloadbalancing:ap-southeast-1:123456789012:targetgroup/devsecops-app/0123456789abcdef"
    }
  }
}

variables {
  db_password     = "test-test-test"
  app_image       = "ghcr.io/tranhuultai/devsecops@sha256:1111111111111111111111111111111111111111111111111111111111111111"
  certificate_arn = "arn:aws:acm:ap-southeast-1:123456789012:certificate/thu-nghiem"
}

run "mang_hai_vung_san_sang" {
  assert {
    condition     = length(aws_subnet.public) == 2 && length(aws_subnet.private) == 2
    error_message = "Cần 2 subnet công khai và 2 subnet riêng (ALB và RDS cần ít nhất hai vùng)."
  }
}

run "s3_khong_cong_khai" {
  assert {
    condition = alltrue([
      for b in [aws_s3_bucket_public_access_block.app, aws_s3_bucket_public_access_block.logs] :
      b.block_public_acls && b.block_public_policy && b.ignore_public_acls && b.restrict_public_buckets
    ])
    error_message = "Bucket S3 phải bật đủ 4 tùy chọn chặn công khai."
  }
}

run "khong_mo_cong_quan_tri_ra_internet" {
  assert {
    condition = alltrue(flatten([
      for sg in [aws_security_group.alb, aws_security_group.app, aws_security_group.db] : [
        for r in sg.ingress : !(contains(coalesce(r.cidr_blocks, []), "0.0.0.0/0") && (
          (r.from_port <= 22 && r.to_port >= 22) || (r.from_port <= 3389 && r.to_port >= 3389)
        ))
      ]
    ]))
    error_message = "Không security group nào được mở cổng 22 hoặc 3389 cho 0.0.0.0/0."
  }

  assert {
    condition     = alltrue([for r in aws_security_group.alb.ingress : r.from_port == 443 && r.to_port == 443])
    error_message = "ALB chỉ được nhận cổng 443."
  }

  assert {
    condition     = alltrue([for r in aws_security_group.app.ingress : length(coalesce(r.cidr_blocks, [])) == 0])
    error_message = "EC2 ứng dụng chỉ nhận từ security group của ALB, không nhận trực tiếp từ dải IP nào."
  }
}

run "rds_khong_cong_khai_va_co_ma_hoa" {
  assert {
    condition     = aws_db_instance.main.publicly_accessible == false && aws_db_instance.main.storage_encrypted == true
    error_message = "RDS phải không công khai và có mã hóa lưu trữ."
  }
}

run "iam_khong_dung_quyen_dai_dien" {
  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.app_read_bucket.statement :
      !contains(s.actions, "*") && !contains(s.actions, "s3:*")
    ])
    error_message = "Quyền của ứng dụng không được dùng * hoặc s3:*."
  }
}

run "ec2_duoc_gia_co" {
  assert {
    condition     = aws_instance.app.metadata_options[0].http_tokens == "required"
    error_message = "EC2 phải bắt buộc IMDSv2."
  }

  assert {
    condition     = aws_instance.app.root_block_device[0].encrypted == true
    error_message = "Ổ đĩa gốc của EC2 phải được mã hóa."
  }

  assert {
    condition     = aws_instance.app.iam_instance_profile == aws_iam_instance_profile.app.name
    error_message = "EC2 phải dùng instance profile gắn IAM role chỉ đọc một bucket."
  }

  assert {
    condition     = strcontains(file("${path.module}/scripts/ec2_bootstrap.sh"), "cosign verify")
    error_message = "Script khởi động phải kiểm chữ ký image trước khi chạy."
  }
}

run "alb_chi_phuc_vu_https" {
  assert {
    condition     = aws_lb_listener.https.protocol == "HTTPS" && startswith(aws_lb_listener.https.ssl_policy, "ELBSecurityPolicy-TLS13")
    error_message = "ALB chỉ phục vụ HTTPS với chính sách TLS 1.3."
  }

  assert {
    condition     = aws_lb.app.drop_invalid_header_fields == true
    error_message = "ALB phải bỏ header HTTP không hợp lệ."
  }

  assert {
    condition     = aws_lb_target_group.app.health_check[0].path == "/health"
    error_message = "Target group phải kiểm sức khỏe qua /health."
  }
}

run "tu_choi_image_dung_tag" {
  command = plan

  variables {
    app_image = "ghcr.io/tranhuultai/devsecops:latest"
  }

  expect_failures = [var.app_image]
}
