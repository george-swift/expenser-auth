#!/bin/bash

set -e  # Exit on error
[[ "$DEBUG" == "true" ]] && set -x  # Enable debugging if DEBUG=true

# 🚀 Colors for readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No color

# Function to log messages with timestamps
log() {
  echo -e "${CYAN}[ $(date +"%Y-%m-%d %H:%M:%S") ]${NC} $1"
}

# Ensure script is executed from project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Load environment variables
if [ -f .env ]; then
  log "${GREEN}Loading environment variables from .env...${NC}"
  set -o allexport
  source .env
  set +o allexport
else
  log "${YELLOW}Warning: No .env file found. Ensure environment variables are set manually.${NC}"
fi

# ✅ Required environment variables
REQUIRED_ENV_VARS=(
  "COGNITO_USER_POOL_ID"
  "COGNITO_USER_POOL_NAME"
  "COGNITO_USER_POOL_ARN"
  "COGNITO_USER_POOL_DOMAIN"
  "COGNITO_APP_CLIENT_ID"
  "COGNITO_APP_CLIENT_SECRET"
  "COGNITO_APP_CLIENT_NAME"
  "API_GATEWAY_INVOKE_URL"
  "API_FRONTEND_URL"
  "SECRET_KEY"
)

# ❌ Check if all required environment variables are set
for var in "${REQUIRED_ENV_VARS[@]}"; do
  if [ -z "${!var}" ]; then
    log "${RED}Error: $var is not set.${NC}"
    exit 1
  fi
done

# ✅ Ensure Terraform is initialized
if [ ! -d ".terraform" ]; then
  log "${GREEN}Initializing Terraform...${NC}"
  terraform init || { log "${RED}Terraform init failed.${NC}"; exit 1; }
fi

# ✅ Apply Terraform changes
log "${GREEN}Applying Terraform changes...${NC}"
terraform apply -auto-approve || { log "${RED}Terraform apply failed.${NC}"; exit 1; }

# ✅ Configure Chalice
log "${GREEN}Configuring Chalice...${NC}"
python chalice_config.py || { log "${RED}Chalice configuration failed.${NC}"; exit 1; }

# ✅ Ensure Chalice is installed
if ! command -v chalice &>/dev/null; then
  log "${RED}Error: Chalice is not installed. Install it using 'pip install chalice'.${NC}"
  exit 1
fi

# ✅ Deploy with Chalice
log "${GREEN}Deploying with Chalice...${NC}"
chalice deploy --stage dev || { log "${RED}Chalice deployment failed.${NC}"; exit 1; }

log "${GREEN}✅ Deployment completed successfully!${NC}"