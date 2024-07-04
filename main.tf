
#########################
# VPC                   #
#########################

module "vpc" {
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-vpc.git?ref=25322b6b6be69db6cca7f167d7b0e5327156a595"

  name             = var.name_prefix
  cidr             = var.vpc_cidr
  azs              = local.azs
  private_subnets  = [for k, v in local.azs : cidrsubnet(var.vpc_cidr, 8, k)]
  public_subnets   = [for k, v in local.azs : cidrsubnet(var.vpc_cidr, 8, k + 4)]
  database_subnets = [for k, v in local.azs : cidrsubnet(var.vpc_cidr, 8, k + 8)]

  create_database_subnet_group           = true
  create_database_subnet_route_table     = true
  create_database_internet_gateway_route = false

  manage_default_network_acl    = true
  manage_default_route_table    = true
  manage_default_security_group = true

  enable_dns_hostnames   = true
  enable_dns_support     = true
  enable_nat_gateway     = true
  single_nat_gateway     = false
  one_nat_gateway_per_az = true

  enable_flow_log                      = true
  create_flow_log_cloudwatch_log_group = true
  create_flow_log_cloudwatch_iam_role  = true
  flow_log_max_aggregation_interval    = 60

  vpc_tags = {
    Name = var.name_prefix
  }
}

#########################
# VPC Endpoints         #
#########################

module "vpc_endpoints" {
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-vpc.git//modules/vpc-endpoints?ref=4a2809c673afa13097af98c2e3c553da8db766a9"

  vpc_id = module.vpc.vpc_id

  create_security_group      = true
  security_group_name_prefix = "${var.name_prefix}-vpc-endpoints-"
  security_group_description = "VPC endpoint security group"
  security_group_rules = {
    ingress_https = {
      description = "HTTPS from VPC"
      cidr_blocks = [module.vpc.vpc_cidr_block]
    }
  }

  endpoints = {
    dynamodb = {
      service         = "dynamodb"
      service_type    = "Gateway"
      route_table_ids = flatten([module.vpc.intra_route_table_ids, module.vpc.private_route_table_ids, module.vpc.public_route_table_ids])
      policy          = data.aws_iam_policy_document.dynamodb_endpoint_policy.json
      tags            = { Name = "dynamodb-vpc-endpoint" }
    },
    ecs = {
      service             = "ecs"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
    },
    ecs_telemetry = {
      create              = false
      service             = "ecs-telemetry"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
    },
    ecr_api = {
      service             = "ecr.api"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
      policy              = data.aws_iam_policy_document.generic_endpoint_policy.json
    },
    ecr_dkr = {
      service             = "ecr.dkr"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
      policy              = data.aws_iam_policy_document.generic_endpoint_policy.json
    },
    rds = {
      service             = "rds"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
      security_group_ids  = [module.db.security_group_id]
    },
    kms = {
      service             = "kms"
      private_dns_enabled = true
      subnet_ids          = module.vpc.database_subnets
    },
    ssm = {
      service             = "ssm"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
    },
    ssmmessages = {
      service             = "ssmmessages"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
    },
    ec2messages = {
      service             = "ec2messages"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
    }
  }

  tags = {
    Name = var.name_prefix
  }
}

data "aws_iam_policy_document" "dynamodb_endpoint_policy" {
  statement {
    effect    = "Deny"
    actions   = ["dynamodb:*"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "aws:sourceVpc"

      values = [module.vpc.vpc_id]
    }
  }
}

data "aws_iam_policy_document" "generic_endpoint_policy" {
  statement {
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "aws:SourceVpc"

      values = [module.vpc.vpc_id]
    }
  }
}

resource "aws_security_group" "private_access" {
  #checkov:skip=CKV2_AWS_5: Placeholder security group, to be assigned to applicable resources, but beyond scope of this module.
  name_prefix = "${var.name_prefix}-private-access"
  description = "Security group for private access from local resources. Permits egress traffic."
  vpc_id      = module.vpc.vpc_id

  egress {
    description = "Permit egress TCP"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    description = "Permit egress UDP"
    from_port   = 0
    to_port     = 65535
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    description = "Permit egress ICMP"
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.name_prefix}-sg-private-access"
  }
}

#########################
# MySQL                 #
#########################

module "db" {
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-rds-aurora.git?ref=7d46e900b31322fd7a0ab0d7f67006ba4836c995"

  name            = "${var.name_prefix}-rds"
  engine          = "aurora-mysql"
  engine_version  = "8.0"
  master_username = "root"
  instances = {
    1 = {
      instance_class = "db.t3.medium"
    }
    2 = {
      instance_class = "db.t3.medium"
    }
  }
  vpc_id               = module.vpc.vpc_id
  db_subnet_group_name = module.vpc.database_subnet_group_name
  security_group_rules = {
    ingress0 = {
      source_security_group_id = aws_security_group.private_access.id
    }
    ingress1 = {
      source_security_group_id = data.aws_security_group.cloud9_security_group.id
    }
    kms_vpc_endpoint = {
      type                     = "egress"
      from_port                = 443
      to_port                  = 443
      source_security_group_id = module.vpc_endpoints.security_group_id
    }
  }

  tags = {
    Name           = var.name_prefix
    Environment    = "dev"
    Classification = "internal"
  }

  manage_master_user_password_rotation              = true
  master_user_password_rotation_schedule_expression = "rate(7 days)"
}

#########################
# EC2 instance          #
#########################

module "ec2_instance" {
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-ec2-instance.git?ref=4f8387d0925510a83ee3cb88c541beb77ce4bad6"

  name                        = "${var.name_prefix}-ec2"
  ami                         = data.aws_ami.amazon_linux_23.id
  create_iam_instance_profile = true
  iam_role_description        = "IAM role for EC2 instance and SSM access"
  iam_role_policies = {
    AmazonSSMManagedInstanceCore = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  }
  instance_type          = "t2.micro"
  vpc_security_group_ids = [aws_security_group.private_access.id]
  subnet_id              = element(module.vpc.private_subnets, 0)

  # Enforces IMDSv2
  metadata_options = {
    "http_endpoint" : "enabled",
    "http_put_response_hop_limit" : 1,
    "http_tokens" : "required"
  }

  tags = {
    Name        = "${var.name_prefix}-ec2"
    Environment = "dev"
  }
}

resource "aws_cloud9_environment_ec2" "cloud9_ssm_instance" {
  name                        = "${var.name_prefix}-cloud9"
  instance_type               = "t2.micro"
  automatic_stop_time_minutes = 30
  image_id                    = "amazonlinux-2023-x86_64"
  connection_type             = "CONNECT_SSM"
  subnet_id                   = element(module.vpc.private_subnets, 0)
  owner_arn                   = length(var.cloud9_instance_owner_arn) > 0 ? var.cloud9_instance_owner_arn : null
}
