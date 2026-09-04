"""
Turns a compact JWT plus a JWKS into a verified TokenPayload.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import partial
from typing import Any

from armasec_lite import jwt
from armasec_lite.exceptions import AuthenticationError, PayloadMappingError
from armasec_lite.schemas import JWK, JWKs
from armasec_lite.token_payload import TokenPayload
from armasec_lite.utilities import log_error, noop


class TokenDecoder:
    """
    Decodes tokens against a set of JSON web keys.
    """

    def __init__(
        self,
        jwks: JWKs,
        algorithm: str = "RS256",
        debug_logger: Callable[..., None] | None = None,
        decode_options_override: dict[str, Any] | None = None,
        permission_extractor: Callable[[dict[str, Any]], list[str]] | None = None,
        jwks_refresher: Callable[[], JWKs] | None = None,
    ):
        """
        Initialize a TokenDecoder.

        Args:
            jwks:                    The public keys available for decoding.
            algorithm:               The only algorithm accepted. Defaults to RS256.
            debug_logger:            A callable such as `logger.debug`.
            decode_options_override: Options overriding the default decode behavior, for
                                     example `{"verify_exp": False}`. One of them,
                                     `verify_signature`, turns off authentication
                                     entirely; it is a testing and debugging switch only.
                                     See the `armasec_lite.jwt` module docstring.
            permission_extractor:    Optional function that extracts permissions from the
                                     decoded token when they are not a top level claim.

                                     Consider the example token:

                                     ```
                                     {
                                       "exp": 1728627701,
                                       "sub": "dfa64115-40b5-46ab-924c-c376e73f631d",
                                       "azp": "my-client",
                                       "resource_access": {
                                         "my-client": {"roles": ["read:stuff"]}
                                       }
                                     }
                                     ```

                                     Permissions live at `resource_access.my-client.roles`,
                                     so an extractor would be:

                                     ```
                                     def my_extractor(decoded_token: dict) -> list[str]:
                                         resource_key = decoded_token["azp"]
                                         return decoded_token["resource_access"][resource_key]["roles"]
                                     ```
            jwks_refresher:          Optional callable returning a freshly fetched JWKs.
                                     Consulted once when a token's `kid` is absent from the
                                     current set, which is what a provider key rotation
                                     looks like from here.
        """
        self.algorithm = algorithm
        self.jwks = jwks
        self.debug_logger = debug_logger if debug_logger else noop
        self.decode_options_override = decode_options_override if decode_options_override else {}
        self.permission_extractor = permission_extractor
        self.jwks_refresher = jwks_refresher

    def _find_key(self, kid: str) -> JWK | None:
        """
        Search the current JWKS for a key with the given id.

        Args:
            kid: The key id from the token's unverified header.
        """
        for jwk in self.jwks.keys:
            self.debug_logger(f"Checking key in jwk: {jwk}")
            if jwk.kid == kid:
                self.debug_logger("Key matches unverified header. Using as decode key.")
                return jwk
        return None

    def get_decode_key(self, token: str) -> JWK:
        """
        Find the public key matching a token's `kid`.

        The `kid` is read from the unverified header, so it is attacker controlled. It is
        used to select a key and for nothing else; the key then has to actually verify the
        signature.

        Args:
            token: The token whose key should be found.
        """
        self.debug_logger("Getting decode key from JWKs")
        unverified_header = jwt.get_unverified_header(token)
        self.debug_logger(f"Extracted unverified header: {unverified_header}")
        kid = unverified_header.get("kid")
        AuthenticationError.require_condition(
            kid,
            "Unverified header doesn't contain 'kid'...not sure how this happened",
        )

        jwk = self._find_key(str(kid))
        if jwk is not None:
            return jwk

        # An unknown kid is what a provider key rotation looks like from here, so try
        # once for a fresh key set before giving up. The refresher is consulted exactly
        # once per decode attempt, never in a loop, so this cannot become a request flood.
        if self.jwks_refresher is not None:
            self.debug_logger(f"No key matched kid {kid!r}; refreshing jwks")
            self.jwks = self.jwks_refresher()
            jwk = self._find_key(str(kid))
            if jwk is not None:
                return jwk

        raise AuthenticationError("Could not find a matching jwk")

    def decode(self, token: str, **claims: Any) -> TokenPayload:
        """
        Decode a JWT into a TokenPayload, checking signatures and claims.

        Args:
            token:  The token to decode.
            claims: Additional constraints, such as `audience` or `issuer`. May include an
                    `options` dict merged over `decode_options_override`.
        """
        self.debug_logger(f"Attempting to decode '{token}'")
        self.debug_logger(f"  checking claims: {claims}")

        options = {**self.decode_options_override, **claims.pop("options", {})}

        with AuthenticationError.handle_errors(
            "Failed to decode token string",
            do_except=partial(log_error, self.debug_logger),
        ):
            payload_dict = jwt.decode(
                token,
                self.get_decode_key(token),
                [self.algorithm],
                options=options,
                **claims,
            )
            self.debug_logger(f"Raw payload dictionary is {payload_dict}")

        with PayloadMappingError.handle_errors(
            "Failed to map decoded token to TokenPayload",
            do_except=partial(log_error, self.debug_logger),
        ):
            if self.permission_extractor is not None:
                self.debug_logger("Attempting to extract permissions.")
                payload_dict = {
                    **payload_dict,
                    "permissions": self.permission_extractor(payload_dict),
                }
                self.debug_logger(
                    f"Payload dictionary with extracted permissions is {payload_dict}"
                )

            self.debug_logger("Attempting to convert to TokenPayload")
            # Validated from one mapping rather than passed as keyword arguments. A token
            # that happens to carry an `original_token` claim would otherwise collide with
            # the keyword and raise TypeError, which surfaces as a 500 rather than a 401.
            # Here the real token simply wins.
            token_payload = TokenPayload.model_validate({**payload_dict, "original_token": token})
            self.debug_logger(f"Built token_payload as {token_payload}")
            return token_payload


def extract_keycloak_permissions(decoded_token: dict[str, Any]) -> list[str]:
    """
    Extract permissions from a Keycloak token.

    Keycloak nests a client's roles inside the "resource_access" claim rather than
    exposing them as a top level claim. Given this token:

    ```
    {
      "exp": 1728627701,
      "sub": "dfa64115-40b5-46ab-924c-c376e73f631d",
      "azp": "my-client",
      "resource_access": {
        "my-client": {"roles": ["read:stuff"]}
      }
    }
    ```

    this extractor returns `["read:stuff"]`.

    Args:
        decoded_token: The decoded token dictionary.
    """
    resource_key = decoded_token["azp"]
    return list(decoded_token["resource_access"][resource_key]["roles"])
