# Find relevant commit hash from https://github.com/haakond/terraform-aws-bastion-host-alternatives/commits/main/
module "bastion_host_alternatives_demo" {
  source                    = "git::https://github.com/haakond/terraform-aws-bastion-host-alternatives.git?ref=c1e31b2287be1e3d0e4f6321b421f3a1da977945"
  cloud9_instance_owner_arn = "arn:aws:sts::1234567890:assumed-role/AWSReservedSSO_AWSAdministratorAccess_08c3cfd6621628f7/chuck@norris.onmicrosoft.com"
}