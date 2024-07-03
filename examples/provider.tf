provider "aws" {
  region  = var.aws_region
  profile = var.profile_cicd
  assume_role {
    role_arn     = "arn:aws:iam::${var.aws_account_id}:role/${var.profile_cicd}"
    session_name = "SESSION_NAME"
    external_id  = "EXTERNAL_ID"
  }
}
