output "lambda_role_arn" {
  description = "ARN of the IAM role used by Lambda functions"
  value       = aws_iam_role.expenser_auth_role.arn
}

output "user_pool_id" {
  description = "ID of the existing Cognito User Pool"
  value       = var.cognito_user_pool_id
}

output "aws_region" {
  description = "AWS Region of the existing Cognito User Pool"
  value       = var.aws_region
}

