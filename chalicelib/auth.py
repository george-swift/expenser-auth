import json
import uuid
import requests
from base64 import b64encode
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_registration_response,
    options_to_json
)
from webauthn.helpers.structs import PublicKeyCredentialDescriptor
from chalice import Blueprint, Response, CognitoUserPoolAuthorizer, CORSConfig
from chalicelib.helpers import (
    base64url_to_bytes,
    bytes_to_base64url,
    generate_random_user_id,
    generate_secret_hash,
    generate_csrf_token,
    verify_csrf_token,
    create_session,
    verify_jwt
)
from chalicelib.settings import cognito_client, settings

USER_POOL_NAME = settings.cognito_user_pool_name
USER_POOL_ARN = settings.cognito_user_pool_arn

cognito_authorizer = CognitoUserPoolAuthorizer(
    USER_POOL_NAME, provider_arns=[USER_POOL_ARN]
)

cors_config = CORSConfig()

auth = Blueprint(__name__)


def check_existing_user(email):
    """Checks if a user with the given email already exists in Cognito."""
    try:
        cognito_client.admin_get_user(
            UserPoolId=settings.cognito_user_pool_id, Username=email
        )
        return True
    except cognito_client.exceptions.UserNotFoundException:
        return False
    except Exception as e:
        auth.log.error(f"Error checking user: {e}")
        return False


@auth.route("/auth/google", methods=["GET"], cors=cors_config)
def google_login():
    """Initiates Google login via Cognito OAuth."""
    state = generate_csrf_token()

    cognito_oauth_url = (
        f"{settings.cognito_user_pool_domain}/oauth2/authorize?"
        f"client_id={settings.cognito_app_client_id}&"
        f"response_type=code&"
        f"scope=email+openid+profile&"
        f"redirect_uri={settings.api_gateway_invoke_url}/auth/google/callback&"
        f"identity_provider=Google&"
        f"state={state}"
    )

    return Response(status_code=302, body="", headers={"Location": cognito_oauth_url})


@auth.route("/auth/google/callback", methods=["GET"], cors=cors_config)
def google_callback():
    """Handles OAuth callback from Cognito and creates a session."""
    request = auth.current_request
    query_params = request.query_params

    code = query_params.get("code")
    state = query_params.get("state")

    if not code or not state:
        return Response(body={"error": "Invalid request"}, status_code=400)

    if not verify_csrf_token(state):
        return Response(body={"error": "CSRF verification failed"}, status_code=403)

    try:
        auth_string = f"{settings.cognito_app_client_id}:{settings.cognito_app_client_secret.get_secret_value()}"
        encoded_auth = b64encode(auth_string.encode()).decode()

        token_response = requests.post(
            f"{settings.cognito_user_pool_domain}/oauth2/token",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "Authorization": f"Basic {encoded_auth}",
            },
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": f"{settings.api_gateway_invoke_url}/auth/google/callback",
            },
            timeout=30,
        )

        if not token_response.ok:
            return Response(body={"error": "Token exchange failed"}, status_code=401)

        tokens = token_response.json()
        access_token = tokens.get("access_token")
        id_token = tokens.get("id_token")
        refresh_token = tokens.get("refresh_token")
        expires_in = tokens.get("expires_in")

        try:
            decoded_token = verify_jwt(id_token)
        except ValueError as e:
            auth.log.error(f"Unable to verify or decode token {e}")
            return Response(body={"error": str(e)}, status_code=401)

        email = decoded_token.get("email")
        user_id = decoded_token.get("sub")

        if not email:
            return Response(
                body={"error": "Invalid token, email not found"}, status_code=400
            )

        session_token = create_session(user_id, email)

        redirect_url = (
            f"{settings.api_frontend_url}/oauth?"
            f"session={session_token}"
            f"&access_token={access_token}"
            f"&id_token={id_token}"
            f"&refresh_token={refresh_token}"
            f"&expires_in={expires_in}"
        )

        return Response(status_code=302, body="", headers={"Location": redirect_url})

    except Exception as e:
        return Response(body={"error": str(e)}, status_code=500)


@auth.route("/auth/register", methods=["POST"], cors=cors_config)
def register_user():
    """Initiates WebAuthn registration and stores user in Cognito."""
    request = auth.current_request
    body = request.json_body

    email = body.get("email")

    if not email:
        return Response(body={"error": "Email is required"}, status_code=400)

    if check_existing_user(email):
        return Response(
            body={
                "error": "This email is already associated with an account. Please log in or use a different email."
            },
            status_code=409,
        )

    webauthn_user_id = generate_random_user_id()
    unique_username = str(uuid.uuid4())

    try:
        cognito_client.admin_create_user(
            UserPoolId=settings.cognito_user_pool_id,
            Username=unique_username,
            UserAttributes=[
                {"Name": "email", "Value": email},
                {"Name": "email_verified", "Value": "true"},
                {"Name": "custom:webauthn_user_id", "Value": webauthn_user_id},
            ],
            MessageAction="SUPPRESS",
        )

        registration_options = generate_registration_options(
            rp_id=settings.rp_id,
            rp_name=settings.rp_name,
            user_name=email,
            user_id=webauthn_user_id.encode("utf-8"),
        )

        return Response(body=options_to_json(registration_options), status_code=200)

    except Exception as e:
        auth.log.error(f"Registration error: {e}")
        return Response(body={"error": "Internal server error"}, status_code=500)


@auth.route("/auth/register/complete", methods=["POST"], cors=cors_config)
def complete_registration():
    """Stores WebAuthn credential ID and public key in Cognito."""
    request = auth.current_request
    body = request.json_body

    email = body.get("email")
    credential = body.get("credential")

    if not email or not credential:
        return Response(body={"error": "Missing required fields."}, status_code=400)

    try:
        user = cognito_client.admin_get_user(
            UserPoolId=settings.cognito_user_pool_id, Username=email
        )

        webauthn_user_id = next(
            (
                attr["Value"]
                for attr in user["UserAttributes"]
                if attr["Name"] == "custom:webauthn_user_id"
            ),
            None,
        )

        if not webauthn_user_id:
            return Response(
                body={"error": "WebAuthn user ID not found."}, status_code=404
            )

        expected_challenge = base64url_to_bytes(credential.get("challenge"))

        registration_verification = verify_registration_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_origin=settings.rp_origin,
            expected_rp_id=settings.rp_id,
        )

        credential_id = bytes_to_base64url(registration_verification.credential_id)
        credential_public_key = bytes_to_base64url(
            registration_verification.credential_public_key
        )

        cognito_client.admin_update_user_attributes(
            UserPoolId=settings.cognito_user_pool_id,
            Username=email,
            UserAttributes=[
                {"Name": "custom:credential_id", "Value": credential_id},
                {"Name": "custom:credential_pub_key", "Value": credential_public_key},
            ],
        )

        return Response(body={"message": "Registration completed."}, status_code=200)

    except Exception as e:
        auth.log.error(f"Error storing WebAuthn credential: {e}")
        return Response(body={"error": "Internal server error"}, status_code=500)


@auth.route("/auth/login", methods=["POST"], cors=cors_config)
def initiate_login():
    """Initiates a WebAuthn authentication challenge for the user."""
    request = auth.current_request
    body = request.json_body

    email = body.get("email")

    if not email:
        return Response(body={"error": "Email is required"}, status_code=400)

    try:
        auth_response = cognito_client.admin_initiate_auth(
            UserPoolId=settings.cognito_user_pool_id,
            ClientId=settings.cognito_app_client_id,
            AuthFlow="CUSTOM_AUTH",
            AuthParameters={
                "USERNAME": email,
                "SECRET_HASH": generate_secret_hash(email),
            },
        )

        challenge_name = auth_response.get("ChallengeName")
        challenge_parameters = auth_response.get("ChallengeParameters", {})
        session = auth_response.get("Session")

        if challenge_name == "CUSTOM_CHALLENGE":
            challenge = challenge_parameters.get("challenge")
            credential_id = challenge_parameters.get("credentialId")

            if not credential_id or not challenge:
                return Response(
                    body={"error": "No WebAuthn credential found."}, status_code=404
                )

            credential_id_bytes = base64url_to_bytes(credential_id)
            challenge_bytes = base64url_to_bytes(challenge)

            authentication_options = generate_authentication_options(
                rp_id=settings.rp_id,
                challenge=challenge_bytes,
                timeout=180000,
                allow_credentials=[
                    PublicKeyCredentialDescriptor(id=credential_id_bytes)
                ],
            )

            return Response(
                body={
                    **json.loads(options_to_json(authentication_options)),
                    "challengeParameters": challenge_parameters,
                    "session": session,
                },
                status_code=200,
            )

        return Response(body={"error": "Unexpected challenge."}, status_code=400)

    except cognito_client.exceptions.UserNotFoundException as e:
        auth.log.error(f"UserNotFoundException: {e}")
        return Response(body={"error": "User not found."}, status_code=404)
    except Exception as e:
        auth.log.error(f"Login initiation error: {e}")
        return Response(body={"error": "Internal server error"}, status_code=500)


@auth.route("/auth/verify", methods=["POST"], cors=cors_config)
def verify_login():
    """Handles Cognito's WebAuthn challenge verification."""
    request = auth.current_request
    body = request.json_body

    email = body.get("email")
    credential = body.get("credential")
    session = body.get("session")

    if not email or not credential or not session:
        return Response(body={"error": "Missing required fields."}, status_code=400)

    try:
        auth_response = cognito_client.admin_respond_to_auth_challenge(
            UserPoolId=settings.cognito_user_pool_id,
            ClientId=settings.cognito_app_client_id,
            ChallengeName="CUSTOM_CHALLENGE",
            Session=session,
            ChallengeResponses={
                "USERNAME": email,
                "SECRET_HASH": generate_secret_hash(email),
                "ANSWER": json.dumps(credential),
            },
        )

        return Response(
            body={
                "accessToken": auth_response["AuthenticationResult"]["AccessToken"],
                "idToken": auth_response["AuthenticationResult"]["IdToken"],
                "refreshToken": auth_response["AuthenticationResult"]["RefreshToken"],
                "expiresIn": auth_response["AuthenticationResult"]["ExpiresIn"],
                "tokenType": auth_response["AuthenticationResult"]["TokenType"],
            },
            status_code=200,
        )

    except cognito_client.exceptions.NotAuthorizedException as e:
        auth.log.error(f"NotAuthorizedException: {e}")
        return Response(body={"error": "Unauthorized."}, status_code=403)
    except cognito_client.exceptions.UserNotFoundException as e:
        auth.log.error(f"UserNotFoundException: {e}")
        return Response(body={"error": "User not found."}, status_code=404)
    except Exception as e:
        auth.log.error(f"Login verification error: {e}")
        return Response(body={"error": "Internal server error"}, status_code=500)


@auth.route("/auth/refresh", methods=["POST"], cors=cors_config)
def refresh_token():
    """Handles refreshing Cognito authentication tokens."""
    request = auth.current_request
    body = request.json_body

    email = body.get("email")
    refresh_token = body.get("refreshToken")

    if not refresh_token:
        return Response(body={"error": "Refresh token is required"}, status_code=400)

    try:
        auth_response = cognito_client.admin_initiate_auth(
            UserPoolId=settings.cognito_user_pool_id,
            ClientId=settings.cognito_app_client_id,
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters={
                "REFRESH_TOKEN": refresh_token,
                "SECRET_HASH": generate_secret_hash(email),
            },
        )

        return Response(
            body={
                "accessToken": auth_response["AuthenticationResult"]["AccessToken"],
                "idToken": auth_response["AuthenticationResult"]["IdToken"],
                "refreshToken": refresh_token,
                "expiresIn": auth_response["AuthenticationResult"]["ExpiresIn"],
                "tokenType": auth_response["AuthenticationResult"]["TokenType"],
            },
            status_code=200,
        )

    except cognito_client.exceptions.NotAuthorizedException:
        return Response(body={"error": "Invalid refresh token"}, status_code=401)
    except Exception as e:
        return Response(body={"error": str(e)}, status_code=500)


@auth.route(
    "/auth/logout", methods=["POST"], cors=cors_config, authorizer=cognito_authorizer
)
def logout():
    """Logs out the user by invalidating their Cognito session."""
    request = auth.current_request

    claims = request.context.get("authorizer", {}).get("claims")

    if not claims:
        auth.log.warning("Missing claims in request. User unauthorized.")
        return Response(body={"error": "Unauthorized"}, status_code=401)

    user_id = claims.get("sub")
    email = claims.get("email")
    provider = json.loads(claims.get("identities", "{}"))

    is_federated_user = provider and provider.get("providerName") == "Google"

    try:
        if is_federated_user:
            logout_url = (
                f"{settings.cognito_user_pool_domain}/logout?client_id={settings.cognito_app_client_id}"
                f"&logout_uri={settings.api_frontend_url}/logout"
            )

            return Response(
                status_code=302,
                body="",
                headers={"Location": logout_url},
            )

        cognito_client.admin_user_global_sign_out(
            UserPoolId=settings.cognito_user_pool_id, Username=email
        )

        return Response(
            body={"message": "User successfully logged out"},
            status_code=200,
        )

    except cognito_client.exceptions.UserNotFoundException:
        return Response(body={"error": "User not found"}, status_code=404)
    except Exception as e:
        auth.log.error(f"Logout error for user {user_id}: {e}")
        return Response(body={"error": str(e)}, status_code=500)


@auth.route(
    "/auth/me", methods=["GET"], cors=cors_config, authorizer=cognito_authorizer
)
def get_authenticated_user():
    """Retrieves the current authenticated user's details."""
    request = auth.current_request

    claims = request.context.get("authorizer", {}).get("claims")

    if not claims:
        auth.log.warning("Missing claims in request. User unauthorized.")
        return Response(body={"error": "Unauthorized"}, status_code=401)

    user_id = claims.get("sub")
    email = claims.get("email")
    picture = claims.get("picture", "")

    if not user_id:
        auth.log.warning("Missing 'sub' claim in Cognito token.")
        return Response(body={"error": "Invalid session"}, status_code=401)

    try:
        return Response(
            body={"userId": user_id, "email": email, "picture": picture},
            status_code=200,
        )

    except Exception as e:
        auth.log.error(f"Error fetching authenticated user {user_id}: {e}")
        return Response(body={"error": str(e)}, status_code=500)
