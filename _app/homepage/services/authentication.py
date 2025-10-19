from typing import List, Union
from dataclasses import dataclass
import logging
import traceback

from django.conf import settings
from webauthn import (
    generate_authentication_options,
    options_to_json,
    verify_authentication_response,
)
from webauthn.helpers import (
    base64url_to_bytes,
    parse_authentication_credential_json,
    parse_authentication_options_json,
)
from webauthn.helpers.structs import (
    PublicKeyCredentialRequestOptions,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
)

from homepage.services import RedisService
from homepage.models import WebAuthnCredential
from homepage.exceptions import InvalidAuthenticationResponse

logger = logging.getLogger(__name__)


@dataclass
class VerifiedAuthentication:
    """
    A custom version of py_webauthn's VerifiedAuthentication since it doesn't output username from
    the response
    """

    credential_id: bytes
    new_sign_count: int
    username: str


class AuthenticationService:
    redis: RedisService

    def __init__(self):
        self.redis = RedisService(db=3)

    def generate_authentication_options(
        self,
        *,
        cache_key: str,
        user_verification: str,
        existing_credentials: List[WebAuthnCredential],
    ) -> PublicKeyCredentialRequestOptions:
        """
        Generate and store authentication options
        """

        if user_verification == "discouraged":
            _user_verification = UserVerificationRequirement.DISCOURAGED
        elif user_verification == "preferred":
            _user_verification = UserVerificationRequirement.PREFERRED
        elif user_verification == "required":
            _user_verification = UserVerificationRequirement.REQUIRED

        authentication_options = generate_authentication_options(
            rp_id=settings.RP_ID,
            user_verification=_user_verification,
            allow_credentials=[
                PublicKeyCredentialDescriptor(
                    id=base64url_to_bytes(cred.id), transports=cred.transports
                )
                for cred in existing_credentials[-64:]
            ],
        )

        self._save_options(cache_key=cache_key, options=authentication_options)

        return authentication_options

    def verify_authentication_response(
        self,
        *,
        cache_key: str,
        existing_credential: WebAuthnCredential,
        response: dict,
    ) -> VerifiedAuthentication:
        try:
            credential = parse_authentication_credential_json(response)
        except Exception as exc:
            error_msg = f"Failed to parse authentication credential: {str(exc)}"
            logger.error(f"{error_msg}\nResponse: {response}\nTraceback: {traceback.format_exc()}")
            raise InvalidAuthenticationResponse(error_msg)

        options = self._get_options(cache_key=cache_key)

        if not options:
            error_msg = f"No authentication options found for session {cache_key}. Options may have expired or were never created."
            logger.error(error_msg)
            raise InvalidAuthenticationResponse(error_msg)

        require_user_verification = False
        if options.user_verification:
            require_user_verification = (
                options.user_verification == UserVerificationRequirement.REQUIRED
            )

        self._delete_options(cache_key=cache_key)

        # Log verification attempt details
        logger.info(
            f"Attempting authentication verification:\n"
            f"  Username: {existing_credential.username}\n"
            f"  Credential ID: {existing_credential.id}\n"
            f"  Expected RP ID: {settings.RP_ID}\n"
            f"  Expected Origin: {settings.RP_EXPECTED_ORIGIN}\n"
            f"  Require User Verification: {require_user_verification}\n"
            f"  Current Sign Count: {existing_credential.sign_count}"
        )

        try:
            verification = verify_authentication_response(
                credential=credential,
                expected_challenge=options.challenge,
                expected_rp_id=settings.RP_ID,
                expected_origin=settings.RP_EXPECTED_ORIGIN,
                require_user_verification=require_user_verification,
                credential_public_key=base64url_to_bytes(existing_credential.public_key),
                credential_current_sign_count=existing_credential.sign_count,
            )
        except Exception as exc:
            # Extract detailed error information
            error_type = type(exc).__name__
            error_details = {
                "error_type": error_type,
                "error_message": str(exc),
                "credential_id": existing_credential.id,
                "username": existing_credential.username,
                "expected_rp_id": settings.RP_ID,
                "expected_origin": settings.RP_EXPECTED_ORIGIN,
                "require_user_verification": require_user_verification,
                "current_sign_count": existing_credential.sign_count,
            }

            # Log full traceback for debugging
            logger.error(
                f"Authentication signature verification failed:\n"
                f"  Error Type: {error_type}\n"
                f"  Error Message: {str(exc)}\n"
                f"  Credential ID: {existing_credential.id}\n"
                f"  Username: {existing_credential.username}\n"
                f"  Expected RP ID: {settings.RP_ID}\n"
                f"  Expected Origin: {settings.RP_EXPECTED_ORIGIN}\n"
                f"  Require User Verification: {require_user_verification}\n"
                f"  Current Sign Count: {existing_credential.sign_count}\n"
                f"  Traceback:\n{traceback.format_exc()}"
            )

            # Build a user-friendly but informative error message
            user_error_msg = f"Could not verify authentication signature: {error_type} - {str(exc)}"

            # Add specific guidance based on common error types
            if "origin" in str(exc).lower():
                user_error_msg += f" (Expected origin: {settings.RP_EXPECTED_ORIGIN})"
            elif "rp" in str(exc).lower() or "relying party" in str(exc).lower():
                user_error_msg += f" (Expected RP ID: {settings.RP_ID})"
            elif "signature" in str(exc).lower():
                user_error_msg += " (Signature validation failed - credential may be invalid or tampered)"
            elif "challenge" in str(exc).lower():
                user_error_msg += " (Challenge validation failed - session may have expired)"
            elif "sign count" in str(exc).lower() or "counter" in str(exc).lower():
                user_error_msg += f" (Sign count mismatch - expected > {existing_credential.sign_count})"

            raise InvalidAuthenticationResponse(user_error_msg)

        confirmed_username = existing_credential.username

        return VerifiedAuthentication(
            credential_id=verification.credential_id,
            new_sign_count=verification.new_sign_count,
            username=confirmed_username,
        )

    def _save_options(self, *, cache_key: str, options: PublicKeyCredentialRequestOptions):
        """
        Store authentication options for the user so we can reference them later
        """
        expiration = options.timeout
        if type(expiration) is int:
            # Store them temporarily, for twice as long as we're telling WebAuthn how long it
            # should give the user to complete the WebAuthn ceremony
            expiration = int(expiration / 1000 * 2)
        else:
            # Default to two minutes since we default timeout to 60 seconds
            expiration = 120

        return self.redis.store(
            key=cache_key, value=options_to_json(options), expiration_seconds=expiration
        )

    def _get_options(self, *, cache_key: str) -> Union[PublicKeyCredentialRequestOptions, None]:
        """
        Attempt to retrieve saved authentication options for the user
        """
        options: str | None = self.redis.retrieve(key=cache_key)
        if options is None:
            return options

        return parse_authentication_options_json(options)

    def _delete_options(self, *, cache_key: str) -> int:
        return self.redis.delete(key=cache_key)
