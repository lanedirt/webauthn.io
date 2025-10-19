from typing import Union, List, Optional
import logging
import traceback

from django.conf import settings
from webauthn import (
    generate_registration_options,
    options_to_json,
    verify_registration_response,
)
from webauthn.helpers import (
    base64url_to_bytes,
    parse_registration_credential_json,
    parse_registration_options_json,
)
from webauthn.helpers.structs import (
    PublicKeyCredentialCreationOptions,
    UserVerificationRequirement,
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    AuthenticatorAttachment,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialHint,
    ResidentKeyRequirement,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier

from homepage.services import RedisService
from homepage.exceptions import InvalidRegistrationSession
from homepage.models import WebAuthnCredential

logger = logging.getLogger(__name__)


class RegistrationService:
    redis: RedisService

    def __init__(self, redis=RedisService(db=2)):
        self.redis = redis

    def generate_registration_options(
        self,
        *,
        username: str,
        attestation: str,
        attachment: str,
        user_verification: str,
        algorithms: List[str],
        existing_credentials: List[WebAuthnCredential],
        discoverable_credential: str,
        hints: List[str],
    ):
        _attestation = AttestationConveyancePreference.NONE

        if attestation == "direct":
            _attestation = AttestationConveyancePreference.DIRECT

        authenticator_selection = AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.DISCOURAGED,
            resident_key=ResidentKeyRequirement.PREFERRED,
        )
        if attachment != "all":
            authenticator_attachment = AuthenticatorAttachment.CROSS_PLATFORM
            if attachment == "platform":
                authenticator_attachment = AuthenticatorAttachment.PLATFORM

            authenticator_selection.authenticator_attachment = authenticator_attachment

        if user_verification == "discouraged":
            authenticator_selection.user_verification = UserVerificationRequirement.DISCOURAGED
        elif user_verification == "preferred":
            authenticator_selection.user_verification = UserVerificationRequirement.PREFERRED
        elif user_verification == "required":
            authenticator_selection.user_verification = UserVerificationRequirement.REQUIRED

        if discoverable_credential == "discouraged":
            authenticator_selection.resident_key = ResidentKeyRequirement.DISCOURAGED
        elif discoverable_credential == "preferred":
            authenticator_selection.resident_key = ResidentKeyRequirement.PREFERRED
        elif discoverable_credential == "required":
            authenticator_selection.resident_key = ResidentKeyRequirement.REQUIRED

        supported_pub_key_algs: Optional[List[COSEAlgorithmIdentifier]] = None
        if len(algorithms) > 0:
            supported_pub_key_algs = []

            if "ed25519" in algorithms:
                supported_pub_key_algs.append(COSEAlgorithmIdentifier.EDDSA)

            if "es256" in algorithms:
                supported_pub_key_algs.append(COSEAlgorithmIdentifier.ECDSA_SHA_256)

            if "rs256" in algorithms:
                supported_pub_key_algs.append(COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256)

            if "mldsa44" in algorithms:
                supported_pub_key_algs.append(COSEAlgorithmIdentifier.ML_DSA_44)

            if "mldsa65" in algorithms:
                supported_pub_key_algs.append(COSEAlgorithmIdentifier.ML_DSA_65)

            if "mldsa87" in algorithms:
                supported_pub_key_algs.append(COSEAlgorithmIdentifier.ML_DSA_87)

        _hints = [PublicKeyCredentialHint(hint) for hint in hints]

        registration_options = generate_registration_options(
            rp_id=settings.RP_ID,
            rp_name=settings.RP_NAME,
            user_name=username,
            user_id=f"webauthnio-{username}".encode(),
            attestation=_attestation,
            authenticator_selection=authenticator_selection,
            supported_pub_key_algs=supported_pub_key_algs,
            exclude_credentials=[
                PublicKeyCredentialDescriptor(
                    id=base64url_to_bytes(cred.id), transports=cred.transports
                )
                for cred in existing_credentials
            ],
            hints=_hints,
        )

        # py_webauthn will default to all supported algorithms on an empty `algorithms` list
        # so clear it manually so we can test out that scenario
        if len(algorithms) == 0:
            registration_options.pub_key_cred_params = []

        self._save_options(username=username, options=registration_options)

        return registration_options

    def verify_registration_response(self, *, username: str, response: dict):
        try:
            credential = parse_registration_credential_json(response)
        except Exception as exc:
            error_msg = f"Failed to parse registration credential: {str(exc)}"
            logger.error(f"{error_msg}\nUsername: {username}\nResponse: {response}\nTraceback: {traceback.format_exc()}")
            raise InvalidRegistrationSession(error_msg)

        options = self._get_options(username=username)

        if not options:
            error_msg = f"No registration options found for user {username}. Options may have expired or were never created."
            logger.error(error_msg)
            raise InvalidRegistrationSession(error_msg)

        require_user_verification = False
        if options.authenticator_selection:
            require_user_verification = (
                options.authenticator_selection.user_verification
                == UserVerificationRequirement.REQUIRED
            )

        self._delete_options(username=username)

        # Log verification attempt details
        logger.info(
            f"Attempting registration verification:\n"
            f"  Username: {username}\n"
            f"  Expected RP ID: {settings.RP_ID}\n"
            f"  Expected Origin: {settings.RP_EXPECTED_ORIGIN}\n"
            f"  Require User Verification: {require_user_verification}\n"
            f"  Supported Algorithms: {[param.alg for param in options.pub_key_cred_params]}"
        )

        try:
            verification = verify_registration_response(
                credential=credential,
                expected_challenge=options.challenge,
                expected_rp_id=settings.RP_ID,
                expected_origin=settings.RP_EXPECTED_ORIGIN,
                require_user_verification=require_user_verification,
                supported_pub_key_algs=[param.alg for param in options.pub_key_cred_params],
            )
        except Exception as exc:
            # Extract detailed error information
            error_type = type(exc).__name__
            error_module = type(exc).__module__
            error_msg = str(exc)

            # Try to get the actual response data for debugging
            response_data = {
                "username": username,
                "expected_rp_id": settings.RP_ID,
                "expected_origin": settings.RP_EXPECTED_ORIGIN,
                "require_user_verification": require_user_verification,
                "supported_algorithms": [param.alg for param in options.pub_key_cred_params],
            }

            # Try to extract actual values from the credential response
            try:
                if hasattr(credential, 'response'):
                    if hasattr(credential.response, 'client_data_json'):
                        import json
                        client_data = json.loads(credential.response.client_data_json)
                        response_data["actual_origin"] = client_data.get("origin")
                        response_data["actual_type"] = client_data.get("type")
                    if hasattr(credential.response, 'authenticator_data'):
                        auth_data = credential.response.authenticator_data
                        if len(auth_data) >= 37:
                            response_data["rp_id_hash"] = auth_data[:32].hex()
                            flags = auth_data[32]
                            response_data["flags"] = {
                                "user_present": bool(flags & 0x01),
                                "user_verified": bool(flags & 0x04),
                                "attested_credential_data": bool(flags & 0x40),
                            }
                if hasattr(credential, 'id'):
                    response_data["credential_id"] = credential.id
                if hasattr(credential, 'type'):
                    response_data["credential_type"] = credential.type
            except Exception as parse_exc:
                logger.warning(f"Could not parse credential response data: {parse_exc}")

            # Log full traceback for debugging
            logger.error(
                f"Registration verification failed:\n"
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
                f"  User Verification Required: {require_user_verification}",
                f"  Supported Algorithms: {[param.alg for param in options.pub_key_cred_params]}",
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

            if "credential_type" in response_data:
                debug_parts.append(f"  Credential Type: {response_data['credential_type']}")

            if "flags" in response_data:
                flags = response_data["flags"]
                debug_parts.extend([
                    "  Authenticator Flags:",
                    f"    User Present: {flags['user_present']}",
                    f"    User Verified: {flags['user_verified']}",
                    f"    Attested Credential Data: {flags['attested_credential_data']}",
                ])
                if require_user_verification and not flags['user_verified']:
                    debug_parts.append(f"    ⚠️  USER VERIFICATION REQUIRED BUT NOT PRESENT!")

            # Add specific guidance based on error type
            debug_parts.append("")
            if "origin" in error_msg.lower():
                debug_parts.append("💡 Origin mismatch - check that your RP_EXPECTED_ORIGIN matches the actual origin")
            elif "rp" in error_msg.lower() or "relying party" in error_msg.lower():
                debug_parts.append("💡 RP ID mismatch - check that your RP_ID matches the domain")
            elif "attestation" in error_msg.lower():
                debug_parts.append("💡 Attestation validation failed - check attestation format and trust path")
            elif "challenge" in error_msg.lower():
                debug_parts.append("💡 Challenge validation failed - session may have expired or challenge was reused")
            elif "algorithm" in error_msg.lower():
                debug_parts.append("💡 Algorithm validation failed - authenticator used unsupported algorithm")
                debug_parts.append(f"   Supported: {[param.alg for param in options.pub_key_cred_params]}")
            elif "user" in error_msg.lower() and "verif" in error_msg.lower():
                debug_parts.append("💡 User verification failed - authenticator didn't perform user verification when required")

            user_error_msg = "\n".join(debug_parts)
            raise InvalidRegistrationSession(user_error_msg)

        return (
            verification,
            options,
        )

    def _save_options(self, username: str, options: PublicKeyCredentialCreationOptions):
        """
        Store registration options for the user so we can reference them later
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
            key=username, value=options_to_json(options), expiration_seconds=expiration
        )

    def _get_options(self, username: str) -> Union[PublicKeyCredentialCreationOptions, None]:
        """
        Attempt to retrieve saved registration options for the user
        """
        options: str | None = self.redis.retrieve(key=username)
        if options is None:
            return options

        return parse_registration_options_json(options)

    def _delete_options(self, username: str) -> int:
        return self.redis.delete(key=username)
