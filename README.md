# 🚀 Expenser Authentication Service Layer

A secure, serverless authentication layer for an expense management app, supporting Passkey (WebAuthn) and Google OAuth. Built with Python (Chalice and Boto3) and deployed on AWS for scalable, phishing-resistant user authentication.

## 📐 Overview

This service handles user authentication through:

- **WebAuthn (Passkeys) –** Modern, passwordless login using FIDO2.
- **Google OAuth –** Alternative authentication through Google.
- **Custom Cognito Lambda Triggers –** For handling custom challenges and pre-signup logic.
- **CSRF Protection –** Secures requests with signed tokens.
- **Stateless Session Management –** With http cookies for frontend/backend sync.

## 📊 High-Level Architecture

```
User → API Gateway (Lambda Proxy) → Cognito → Chalice Lambda Functions
```

| Component          | Responsibility                                                              |
| ------------------ | --------------------------------------------------------------------------- |
| Frontend (Next.js) | Handles user interactions and cookies                                       |
| API Gateway        | Secure entry point for auth requests                                        |
| Lambda (Chalice)   | Custom logic for WebAuthn and OAuth challenge                               |
| Cognito            | Triggers define and verify challenges. Stores WebAuthn credentials securely |

### 📂 Project Structure

```
.
├── README.md                  # Documentation
├── deploy.sh                  # Unified deployment script
├── .env.example               # Environment template
├── app.py                     # Main Chalice app
├── chalicelib/
│    ├── auth.py               # Authentication handlers
│    ├── auth_challenges.py    # Cognito custom challenge logic
│    ├── helpers.py            # Utility functions
│    └── settings.py           # Pydantic settings for environment variables and secrets
└── terraform/
     ├── main.tf               # AWS resources (Cognito, Lambda, etc.)
     ├── variables.tf          # Input variables
     └── outputs.tf            # Outputs for automation
```

## 🔒 Authentication Flow (Step-by-Step)

### **1. Passkey (WebAuthn) Authentication**

- **User registers** with a passkey credential collected via the WebAuthn API during sign-up.
- Credential is **securely stored** in Cognito as a custom attribute (`credential_pub_key`).
- During sign-in, the passkey is verified using a custom Cognito challenge, and user is authenticated if valid.

### **2. Google OAuth Sign-In**

- User authenticates via Google.
- Tokens are verified and generated in Cognito
- Session is created and user is redirected to a protected route in frontend.
- Session is established using cookies.

## ⚙️ Configuration & Environment Variables

The following environment variables and secrets are managed using **Pydantic Settings Management (`chalicelib/settings.py`)**:

- Cognito User Pool & App Client Configuration
- API Gateway & Frontend URLs
- Security Settings (CSRF Protection, WebAuthn Relying Party Config)

```python
from pydantic_settings import BaseSettings
from pydantic import SecretStr, AnyHttpUrl, Field

class AuthSettings(BaseSettings):
    cognito_user_pool_id: str = Field(...)
    cognito_user_pool_name: str = Field(...)
    cognito_user_pool_arn: str = Field(...)
    cognito_user_pool_domain: str = Field(...)
    cognito_app_client_id: str = Field(...)
    cognito_app_client_secret: SecretStr = Field(...)
    cognito_app_client_name: str = Field(...)
    api_gateway_invoke_url: str = Field(...)
    api_frontend_url: str = Field(...)
    secret_key: SecretStr = Field(...)
    rp_id: str = Field(default="localhost")
    rp_name: str = Field(default="Local Host")
    rp_origin: str = Field(default="https://localhost:3000")
```

## 🛠️ Setup & Deployment

### 📌 Prerequisites

- **AWS CLI** (configured with valid credentials)
- **Terraform** (v1.6+)
- **Python 3.12**

### 🧑‍💻 Local Development

1. Clone the Repository

```bash
git clone https://github.com/george-swift/expenser-auth.git
cd expenser-auth
```

2. Set Up Environment

```bash
cp .env.example .env # Populate .env with a Cognito pool config, API Gateway invoke url, frontend url and a 32 char secret
```

3. Install Dependencies

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

4. Run Locally

```bash
chalice local
```

### 🚀 Deploying Resources to AWS

1. Ensure that the deployment script is executable

```sh
chmod +x ./deploy.sh
```

2. Run the script to initialize terraform, apply changes, configure Chalice and deploy

```bash
./deploy.sh
```

### 🔒 Security Considerations

- ✅ Phishing-Resistant Authentication via Passkeys
- ✅ IAM Least Privilege – Minimal permissions for Lambda and DynamoDB
- ✅ Session Isolation – Per-user stateless cookies
- ✅ CSRF Defense – Signed tokens for cross-origin protection

### 🔭 Logging and Monitoring

- AWS CloudWatch log groups for Lambda invocations
- AWS X-ray for tracing insights

### ⏳ Next Objectives

- Add Apple OAuth – Diversify sign-in options.

### 🛎️ Support

For issues or questions, open a GitHub Issue
