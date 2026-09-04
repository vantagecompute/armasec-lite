"""
Turns a compact JWT plus a JWKS into a verified TokenPayload.

Sits between `TokenManager`, which pulls the token out of a header, and
`armasec_lite.jwt`, which does the cryptography. Its job is key selection, option
merging, and mapping the resulting claim dictionary onto a `TokenPayload`.

## Key selection is not trust

`get_decode_key` reads the token's `kid` from its unverified header, so the value is
attacker controlled. It is used to look a key up in the JWKS and for nothing else: the key
it selects still has to verify the signature, so choosing a different one only means the
token fails. The same is true of the `alg` in that header, which is ignored entirely; the
algorithm comes from `DomainConfig` by way of the constructor.

## Key rotation

An unknown `kid` is what a provider key rotation looks like from here. When a
`jwks_refresher` is configured, which `TokenSecurity` always does, an unmatched `kid`
triggers exactly one refetch attempt per decode, never a loop. The refresher itself is
rate limited in `openid_config_loader`, so a flood of tokens carrying invented key ids
cannot be turned into a flood of outbound requests. Without a refresher the decoder simply
fails, which is upstream armasec's behavior: every request returns 401 until the service is
restarted.

## Two error types, two very different statuses

Signature and claim failures are `AuthenticationError` and answer 401. A failure to map
the decoded claims onto a `TokenPayload`, which in practice means a `permission_extractor`
that does not match the token's shape, is `PayloadMappingError` and answers 500. The split
is deliberate: the second is a server misconfiguration, and telling the client to fix its
token would send it after the wrong problem. The two `handle_errors` blocks in `decode`
are what draw the line.
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

    One decoder exists per configured domain, built by `TokenSecurity` and held for the
    life of the process. It is not immutable: `self.jwks` is replaced in place when a key
    rotation is detected, which is how the refreshed key set reaches subsequent requests
    without rebuilding anything.

    Attributes:
        algorithm:               The single algorithm accepted, from `DomainConfig`. It
                                 becomes the one-element allowlist `jwt.decode` checks a
                                 token's `alg` against, so a token asking for anything
                                 else is refused before a key is touched.
        jwks:                    The current key set. Replaced by `jwks_refresher` when a
                                 token presents an unknown `kid`.
        debug_logger:            A callable such as `logger.debug`, defaulting to `noop`.
        decode_options_override: Options merged under any passed to `decode`. One of them,
                                 `verify_signature`, disables authentication entirely and
                                 is a testing switch only.
        permission_extractor:    Optional function pulling permissions out of a claim that
                                 is not a top level `permissions`.
        jwks_refresher:          Optional callable returning a freshly fetched key set,
                                 consulted at most once per decode.
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
        Store the keys, algorithm and options this decoder will use. No work is done here.

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

        Returns:
            The matching key, or None when the current set has no key with that id.
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

        On a miss, and only when a `jwks_refresher` is configured, the key set is refetched
        once and searched again. That covers a provider key rotation without a restart. The
        refresher is consulted exactly once per call, never in a loop, and is itself rate
        limited, so an attacker sending tokens with invented key ids cannot amplify them
        into outbound requests.

        Args:
            token: The token whose key should be found.

        Returns:
            The JWK whose `kid` matches the token's. Selecting it proves nothing on its
            own; the signature check that follows is what decides the token's fate.

        Raises:
            AuthenticationError: The token has no `kid` header, or no key matches it even
                after a refresh. Maps to 401. In practice the second case means either a
                token from a different provider or a rotation this process has not caught
                up with, and the debug logger distinguishes them.
            InvalidTokenError: The token is not a well formed JWS, so its header could not
                be read at all. A subclass of `AuthenticationError`; also 401.
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

        The entry point for the whole verification path: it selects the key, hands the
        token to `armasec_lite.jwt.decode` for signature and claim checks, then applies any
        `permission_extractor` and builds the payload model.

        Args:
            token:  The token to decode.
            claims: Additional constraints, such as `audience` or `issuer`. May include an
                    `options` dict merged over `decode_options_override`, with the passed
                    options winning on collision.

        Returns:
            The verified payload, with `original_token` set to the input token. The payload
            is built from one mapping rather than from keyword arguments, deliberately: a
            token carrying its own `original_token` claim would otherwise collide with the
            keyword and raise `TypeError`, surfacing as a 500 where a 401 belongs. Here the
            real token simply wins.

        Raises:
            AuthenticationError: The token is malformed, its signature does not verify, or
                a claim check failed. The subclasses in `armasec_lite.jwt` carry the
                specific reason, and all of them map to 401.
            PayloadMappingError: The configured `permission_extractor` did not match a path
                in the decoded token, or the claims did not validate as a `TokenPayload`
                (most often a token with no `sub`). Maps to 500, because that is a server
                misconfiguration rather than a bad request, and a 401 would send the client
                after the wrong problem.
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

    Pass it as `DomainConfig(permission_extractor=extract_keycloak_permissions)`. It is
    called only after the signature has verified, so the claims it reads are trustworthy.

    Args:
        decoded_token: The decoded token dictionary.

    Returns:
        The roles granted to the client named by the token's `azp` claim.

    Raises:
        KeyError: The token has no `azp`, no `resource_access`, or no entry under
            `resource_access` for its own `azp`. `TokenDecoder.decode` catches this and
            re-raises it as a `PayloadMappingError`, which is a 500: a Keycloak extractor
            pointed at a provider that does not shape its tokens this way is a
            configuration mistake, not a bad token.
    """
    resource_key = decoded_token["azp"]
    return list(decoded_token["resource_access"][resource_key]["roles"])
