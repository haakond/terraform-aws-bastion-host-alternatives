# Find relevant commit hash from https://github.com/haakond/terraform-aws-bastion-host-alternatives/commits/main/
#
# Note: If you provision this module "manually", remove cloud9_instance_owner_arn.
# If you provision this module through a CI/CD pipeline, specify the ARN for your IAM principal, otherwise the Cloud9 instance will not be visible in the AWS Console
#
module "bastion_host_alternatives_demo" {
  source = "git::https://github.com/haakond/terraform-aws-bastion-host-alternatives.git?ref=c1e31b2287be1e3d0e4f6321b421f3a1da977945"
  #cloud9_instance_owner_arn = "arn:aws:sts::1234567890:assumed-role/AWSReservedSSO_AWSAdministratorAccess_08c3cfd6621628f7/chuck@norris.onmicrosoft.com"
  # Commented out on purpose, see comment above.
}