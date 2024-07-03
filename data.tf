data "aws_caller_identity" "current" {}
data "aws_canonical_user_id" "current" {}
data "aws_cloudfront_log_delivery_canonical_user_id" "cloudfront" {}
data "aws_region" "current" {}
data "aws_availability_zones" "available" {}

data "aws_ami" "amazon_linux_23" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023*-x86_64"]
  }
}

data "aws_security_group" "cloud9_security_group" {
  filter {
    name = "tag:aws:cloud9:environment"
    values = [
      aws_cloud9_environment_ec2.cloud9_ssm_instance.id
    ]
  }
}