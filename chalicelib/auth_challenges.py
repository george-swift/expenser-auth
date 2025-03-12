import json
import logging
import time
from webauthn import verify_authentication_response
from chalice import Blueprint
from chalicelib.helpers import (
    base64url_to_bytes,
    bytes_to_base64url,
    generate_challenge
)
from chalicelib.settings import settings

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

auth_challenges = Blueprint(__name__)

CUSTOM_CHALLENGE = "CUSTOM_CHALLENGE"
CHALLENGE_EXPIRY_SECONDS = 300
MAX_FAILED_ATTEMPTS = 5


@auth_challenges.lambda_function(name="presignup")
def presignup(event, context):
    """
    Auto-verifies user email before Cognito signs up user.
    """
    event["response"]["autoVerifyEmail"] = True

    return event


@auth_challenges.lambda_function(name="define_auth_challenge")
def define_auth_challenge(event, context):
    """Defines the authentication challenge flow in Cognito."""
    logger.info("Define Auth Challenge Event: %s", json.dumps(event))

    session = event["request"]["session"]
    response = event["response"]

    if not session:
        response["challengeName"] = CUSTOM_CHALLENGE
        response["issueTokens"] = False
        response["failAuthentication"] = False
        logger.info("Initial challenge issued.")
        return event

    failed_attempts = sum(
        1 for challenge in session if not challenge.get("challengeResult", False)
    )

    if failed_attempts >= MAX_FAILED_ATTEMPTS:
        response["issueTokens"] = False
        response["failAuthentication"] = True
        logger.warning("Max failed attempts reached. Authentication failed.")
        return event

    last_challenge = session[-1]
    challenge_success = last_challenge.get("challengeResult", False)

    if challenge_success:
        response["issueTokens"] = True
        response["failAuthentication"] = False
        logger.info("Challenge passed. Issuing tokens.")
    else:
        response["challengeName"] = CUSTOM_CHALLENGE
        response["issueTokens"] = False
        response["failAuthentication"] = False
        logger.info(
            f"Challenge failed. Reattempting ({failed_attempts}/{MAX_FAILED_ATTEMPTS})."
        )

    return event


@auth_challenges.lambda_function(name="create_auth_challenge")
def create_auth_challenge(event, context):
    """Creates a WebAuthn authentication challenge for Cognito users."""
    logger.info("Create Auth Challenge Event: %s", json.dumps(event))

    user_attributes = event.get("request", {}).get("userAttributes", {})
    credential_id = user_attributes.get("custom:credential_id")

    if not credential_id:
        logger.error("No WebAuthn credential ID found for user.")
        event["response"]["failAuthentication"] = True
        return event

    challenge_nonce = bytes_to_base64url(generate_challenge())
    challenge_expiry = int(time.time()) + CHALLENGE_EXPIRY_SECONDS

    event["response"]["publicChallengeParameters"] = {
        "challenge": challenge_nonce,
        "credentialId": credential_id,
    }

    event["response"]["privateChallengeParameters"] = {
        "challenge": challenge_nonce,
        "expiresAt": challenge_expiry,
    }

    event["response"]["challengeMetadata"] = "WebAuthnChallenge"

    logger.info("WebAuthn challenge created for user")

    return event


@auth_challenges.lambda_function(name="verify_auth_challenge_response")
def verify_auth_challenge_response(event, context):
    """Verifies the WebAuthn authentication challenge response."""
    logger.info("Verify Auth Challenge Event: %s", json.dumps(event))

    event_request = event.get("request", {})
    challenge_params = event_request.get("privateChallengeParameters", {})
    challenge_answer = json.loads(event_request.get("challengeAnswer", "{}"))

    if not challenge_params or not challenge_answer:
        logger.error("Missing challenge parameters or challenge answer.")
        event["response"]["answerCorrect"] = False
        return event

    challenge_nonce = challenge_params.get("challenge")
    challenge_expiry = int(challenge_params.get("expiresAt", 0))

    if time.time() > challenge_expiry:
        logger.error("Challenge expired.")
        event["response"]["answerCorrect"] = False
        return event

    try:
        if challenge_answer.get("challenge") != challenge_nonce:
            logger.error("Challenge nonce mismatch.")
            event["response"]["answerCorrect"] = False
            return event

        credential_public_key = event["request"]["userAttributes"].get(
            "custom:credential_pub_key"
        )

        if not credential_public_key:
            logger.error("User does not have a registered WebAuthn credential.")
            event["response"]["answerCorrect"] = False
            return event

        authentication_verification = verify_authentication_response(
            credential=challenge_answer,
            expected_challenge=base64url_to_bytes(challenge_nonce),
            expected_rp_id=settings.rp_id,
            expected_origin=settings.rp_origin,
            credential_public_key=base64url_to_bytes(credential_public_key),
            credential_current_sign_count=0,  # Replace with a known number of times the authenticator was used to prevent replay attacks.
        )

        logger.info(f"WebAuthn verification result: {authentication_verification}")

        if authentication_verification.user_verified:
            logger.info("WebAuthn authentication successful.")
            event["response"]["answerCorrect"] = True
        else:
            logger.error(
                "WebAuthn authentication failed despite successful verification."
            )
            event["response"]["answerCorrect"] = False

    except Exception as e:
        logger.error(f"Unexpected verification error: {str(e)}")
        event["response"]["answerCorrect"] = False

    return event
