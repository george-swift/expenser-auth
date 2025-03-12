import os
import hmac
import hashlib
import secrets
import time
from jose import jwt
from base64 import b64encode, urlsafe_b64encode, urlsafe_b64decode
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from chalicelib.settings import settings


def bytes_to_base64url(val: bytes) -> str:
    """
    Base64URL-encode the provided bytes
    """
    return urlsafe_b64encode(val).decode("utf-8").rstrip("=")


def base64url_to_bytes(val: str) -> bytes:
    """
    Convert a Base64URL-encoded string to bytes.
    """
    # Padding is optional in Base64URL. Unfortunately, Python's decoder requires the
    # padding. Given the fact that urlsafe_b64decode will ignore too much padding, we can
    # tack on a constant amount of padding to ensure encoded values can always be decoded.
    return urlsafe_b64decode(f"{val}===")


def generate_challenge() -> bytes:
    """
    Create a random value for the authenticator to sign as recommended in
    https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges:

    "In order to prevent replay attacks, the challenges MUST contain enough entropy to make
    guessing them infeasible. Challenges SHOULD therefore be at least 16 bytes long."
    """
    return secrets.token_bytes(64)


def generate_random_user_id() -> str:
    """Generates a secure random user ID for WebAuthn."""
    return bytes_to_base64url(os.urandom(32))


def generate_secret_hash(username: str) -> str:
    """
    Generates the Secret Hash parameter required in Cognito user pool authentication APIs.
    """
    digest = hmac.new(
        settings.cognito_app_client_secret.get_secret_value().encode("utf-8"),
        (username + settings.cognito_app_client_id).encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return b64encode(digest).decode()


def generate_csrf_token() -> str:
    """Generates a signed CSRF token with timestamp."""
    serializer = URLSafeTimedSerializer(settings.secret_key.get_secret_value())
    token = serializer.dumps(str(int(time.time())))
    return token


def verify_csrf_token(token: str) -> bool:
    """
    Verifies the CSRF token received from the OAuth callback.

    - Ensures the token is valid and wasn't tampered with.
    - Checks expiration to prevent replay attacks.
    """
    try:
        serializer = URLSafeTimedSerializer(settings.secret_key.get_secret_value())
        serializer.loads(token, max_age=300)
        return True
    except (BadSignature, SignatureExpired):
        return False


def create_session(user_id: str, email: str) -> str:
    """Creates a secure session token for the user."""
    payload = {
        "sub": user_id,
        "email": email,
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()),
    }

    session_token = jwt.encode(
        payload, settings.secret_key.get_secret_value(), algorithm="HS256"
    )
    return session_token


def verify_jwt(token):
    """Decodes a Cognito JWT ID token without signature verification as that is done implicitly."""
    return jwt.decode(
        token,
        key="",
        options={
            "verify_signature": False,
            "verify_at_hash": False,
            "verify_aud": False,
            "verify_iss": False,
        },
    )
