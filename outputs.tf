
output "cloud9_security_group_id" {
  value       = data.aws_security_group.cloud9_security_group.id
  description = "Cloud9 Security Group ID"
  sensitive   = false
}
