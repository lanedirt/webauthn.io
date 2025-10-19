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
            error_module = type(exc).__module__
            error_msg = str(exc)

            # Try to get the actual response data for debugging
            response_data = {
                "credential_id": existing_credential.id,
                "username": existing_credential.username,
                "expected_rp_id": settings.RP_ID,
                "expected_origin": settings.RP_EXPECTED_ORIGIN,
                "require_user_verification": require_user_verification,
                "current_sign_count": existing_credential.sign_count,
            }

            # Try to extract actual values from the credential response
            try:
                if hasattr(credential, 'response'):
                    if hasattr(credential.response, 'client_data_json'):
                        import json
                        from base64 import b64decode
                        client_data = json.loads(credential.response.client_data_json)
                        response_data["actual_origin"] = client_data.get("origin")
                        response_data["actual_type"] = client_data.get("type")
                    if hasattr(credential.response, 'authenticator_data'):
                        auth_data = credential.response.authenticator_data
                        # Extract RP ID hash (first 32 bytes)
                        if len(auth_data) >= 37:
                            response_data["rp_id_hash"] = auth_data[:32].hex()
                            # Extract flags (byte 32)
                            flags = auth_data[32]
                            response_data["flags"] = {
                                "user_present": bool(flags & 0x01),
                                "user_verified": bool(flags & 0x04),
                                "backup_eligible": bool(flags & 0x08),
                                "backup_state": bool(flags & 0x10),
                                "attested_credential_data": bool(flags & 0x40),
                                "extension_data": bool(flags & 0x80),
                            }
                            # Extract sign count (bytes 33-36)
                            response_data["actual_sign_count"] = int.from_bytes(auth_data[33:37], byteorder='big')
            except Exception as parse_exc:
                logger.warning(f"Could not parse credential response data: {parse_exc}")

            # Log full traceback for debugging
            logger.error(
                f"Authentication signature verification failed:\n"
                f"  Error Type: {error_module}.{error_type}\n"
                f"  Error Message: {error_msg}\n"
                f"  Response Data: {response_data}\n"
                f"  Traceback:\n{traceback.format_exc()}"
            )

            # Build a detailed, user-friendly error message
            debug_parts = [
                f"Verification failed: {error_type}",
                f"Message: {error_msg}",
                f"",
                "Verification Parameters:",
                f"  Expected RP ID: {settings.RP_ID}",
                f"  Expected Origin: {settings.RP_EXPECTED_ORIGIN}",
                f"  Expected Sign Count: > {existing_credential.sign_count}",
                f"  User Verification Required: {require_user_verification}",
            ]

            # Add actual values if we extracted them
            if "actual_origin" in response_data:
                debug_parts.extend([
                    "",
                    "Actual Values from Response:",
                    f"  Actual Origin: {response_data['actual_origin']}",
                ])
                if response_data["actual_origin"] != settings.RP_EXPECTED_ORIGIN:
                    debug_parts.append(f"  ⚠️  ORIGIN MISMATCH!")

            if "actual_sign_count" in response_data:
                debug_parts.append(f"  Actual Sign Count: {response_data['actual_sign_count']}")
                if response_data["actual_sign_count"] <= existing_credential.sign_count:
                    debug_parts.append(f"  ⚠️  SIGN COUNT NOT INCREMENTED! (Got {response_data['actual_sign_count']}, expected > {existing_credential.sign_count})")

            if "flags" in response_data:
                flags = response_data["flags"]
                debug_parts.extend([
                    "  Authenticator Flags:",
                    f"    User Present: {flags['user_present']}",
                    f"    User Verified: {flags['user_verified']}",
                ])
                if require_user_verification and not flags['user_verified']:
                    debug_parts.append(f"    ⚠️  USER VERIFICATION REQUIRED BUT NOT PRESENT!")

            # Add specific guidance based on error type
            debug_parts.append("")
            if "origin" in error_msg.lower():
                debug_parts.append("💡 Origin mismatch - check that your RP_EXPECTED_ORIGIN matches the actual origin")
            elif "rp" in error_msg.lower() or "relying party" in error_msg.lower():
                debug_parts.append("💡 RP ID mismatch - check that your RP_ID matches the domain")
            elif "signature" in error_msg.lower():
                debug_parts.append("💡 Signature validation failed - possible causes:")
                debug_parts.append("   - Wrong public key stored for this credential")
                debug_parts.append("   - Credential was created on different RP ID/origin")
                debug_parts.append("   - Challenge mismatch or tampered response")
            elif "challenge" in error_msg.lower():
                debug_parts.append("💡 Challenge validation failed - session may have expired or challenge was reused")
            elif "sign count" in error_msg.lower() or "counter" in error_msg.lower():
                debug_parts.append("💡 Sign count validation failed - authenticator may have been cloned or reset")
            elif "user" in error_msg.lower() and "verif" in error_msg.lower():
                debug_parts.append("💡 User verification failed - authenticator didn't perform user verification when required")

            user_error_msg = "\n".join(debug_parts)
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
