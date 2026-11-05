output "alb_dns_name" {
  description = "Tên miền của ALB; trỏ bản ghi DNS của nhóm vào đây rồi gọi https://<tên miền>/health"
  value       = aws_lb.app.dns_name
}

output "app_instance_id" {
  description = "ID của EC2 chạy ứng dụng"
  value       = aws_instance.app.id
}
