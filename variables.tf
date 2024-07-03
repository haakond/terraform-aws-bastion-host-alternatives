variable "vpc_cidr" {
  type        = string
  default     = "10.1.0.0/16"
  description = "VPC CIDR range."
}

variable "name_prefix" {
  type        = string
  default     = "bastion-alternative-demo"
  description = "Name prefix for provisioned resources."
}

variable "cloud9_instance_owner_arn" {
  type        = string
  description = "The ARN of the environment owner. This can be ARN of any AWS IAM principal. Defaults to the environment's creator, but if provisioned by CI/CD, it will not be visible in the AWS Console."
}