variable "aws_region" {
  type        = string
  description = "AWS region where resources will be created"
  default     = "us-east-1"
}

variable "aws_account_id" {
  type        = string
  description = "AWS Account ID where resources will be created"
  validation {
    condition     = can(regex("^\\d{12}$", var.aws_account_id))
    error_message = "AWS Account ID must be 12 digits."
  }
}

variable "cognito_user_pool_id" {
  type        = string
  description = "ID of the existing Cognito User Pool to attach Lambda triggers to"
}

variable "cognito_app_client_auth_role" {
  type        = string
  description = "Name of the IAM role for Lambda functions"
  default     = "expenser-auth-role"
}

variable "cognito_app_client_auth_policy" {
  type        = string
  description = "Name of the IAM policy for Lambda functions"
  default     = "expenser-auth-policy"
}
