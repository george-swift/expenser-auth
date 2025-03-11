from typing import Tuple, Type
from functools import lru_cache
from pydantic_settings import (
    BaseSettings,
    SettingsConfigDict,
    PydanticBaseSettingsSource
)
from pydantic import SecretStr, Field, field_validator
import re
import boto3


class AuthSettings(BaseSettings):
    """Environment variables for authentication and authorization"""

    model_config = SettingsConfigDict(case_sensitive=False, env_file_encoding="utf-8")

    # Cognito User Pool
    cognito_user_pool_id: str = Field(..., description="Cognito User Pool ID")
    cognito_user_pool_name: str = Field(..., description="Cognito User Pool Name")
    cognito_user_pool_arn: str = Field(..., description="Cognito User Pool ARN")
    cognito_user_pool_domain: str = Field(..., description="Cognito User Pool Domain")

    # Cognito App Client
    cognito_app_client_id: str = Field(..., description="Cognito App Client ID")
    cognito_app_client_secret: SecretStr = Field(
        ..., description="Cognito App Client Secret"
    )
    cognito_app_client_name: str = Field(..., description="Cognito App Client Name")

    # API Endpoint
    api_gateway_invoke_url: str = Field(..., description="API Gateway Invoke URL")
    api_frontend_url: str = Field(..., description="Frontend Application URL")

    # Security
    secret_key: SecretStr = Field(..., description="Secret Key for CSRF Protection")

    # Relying Party
    rp_id: str = Field(default="localhost", description="WebAuthn Relying Party ID")
    rp_name: str = Field(
        default="Local Host", description="WebAuthn Relying Party Name"
    )
    rp_origin: str = Field(
        default="https://localhost:3000", description="WebAuthn Relying Party Origin"
    )

    @field_validator("cognito_user_pool_arn")
    def validate_arn(cls, v):
        """Validate AWS ARN format"""
        arn_pattern = r"^arn:aws:cognito-idp:[a-z0-9-]+:\d{12}:userpool/[a-zA-Z0-9-_]+$"
        if not re.match(arn_pattern, v):
            raise ValueError("Invalid Cognito User Pool ARN format")
        return v

    @field_validator("cognito_user_pool_id")
    def validate_pool_id(cls, v):
        """Validate Cognito User Pool ID format"""
        pool_id_pattern = r"^[a-z0-9-]+_[A-Za-z0-9]+$"
        if not re.match(pool_id_pattern, v):
            raise ValueError("Invalid Cognito User Pool ID format")
        return v

    @field_validator("secret_key")
    def validate_secret_key(cls, v):
        """Ensure secret key is at least 32 characters and not weak"""
        weak_keys = {"123456", "password", "admin", "qwerty"}
        if len(v.get_secret_value()) < 32 or v.get_secret_value() in weak_keys:
            raise ValueError(
                "Secret key must be at least 32 characters and not easily guessable"
            )
        return v
    
    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: Type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> Tuple[PydanticBaseSettingsSource, ...]:
        """Ensure environment variables and dotenv file settings are prioritized"""
        return env_settings, init_settings, file_secret_settings


@lru_cache()
def get_settings() -> AuthSettings:
    """
    Create cached instance of settings.
    Using lru_cache to ensure settings are only parsed once.
    """
    return AuthSettings()


# Create a global settings instance
settings = get_settings()

# Create a shared client
cognito_client = boto3.client("cognito-idp")
