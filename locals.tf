locals {
  azs            = slice(data.aws_availability_zones.available.names, 0, 2)
  aws_account_id = data.aws_caller_identity.current.account_id
}