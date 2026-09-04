"""
Extracts a bearer token from request headers and decodes it.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from armasec_lite.exceptions import AuthenticationError
from armasec_lite.schemas import OpenidConfig
from armasec_lite.token_decoder import TokenDecoder
from armasec_lite.token_payload import TokenPayload
from armasec_lite.utilities import noop


class TokenManager:
    """
    Unpacks a JWT from request headers and hands it to a TokenDecoder.
    """

    auth_scheme = "bearer"
    header_key = "Authorization"

    def __init__(
        self,
        openid_config: OpenidConfig,
        token_decoder: TokenDecoder,
        audience: str | None = None,
        ignore_audience: bool = False,
        verify_issuer: bool = True,
        debug_logger: Callable[..., None] | None = None,
        decode_options_override: dict[str, Any] | None = None,
    ):
        """
        Initialize a TokenManager.

        Args:
            openid_config:           The provider's configuration, used for the issuer.
            token_decoder:           The decoder used to verify jwts.
            audience:                An optional audience to check in decoded tokens.
            ignore_audience:         If true and audience is None, skip audience checks.
            verify_issuer:           Check the token's `iss` against the provider's issuer.
                                     Upstream armasec never performed this check; pass
                                     False for exact upstream behavior.
            debug_logger:            A callable such as `logger.debug`.
            decode_options_override: Options overriding the default decode behavior.
        """
        self.audience = audience
        self.ignore_audience = ignore_audience
        self.verify_issuer = verify_issuer
        self.debug_logger = debug_logger if debug_logger else noop
        self.decode_options_override = decode_options_override if decode_options_override else {}

        self.openid_config = openid_config
        self.token_decoder = token_decoder

    def unpack_token_from_header(self, headers: Mapping[str, str]) -> str:
        """
        Pull the bearer token out of a request's headers.

        Args:
            headers: The headers to read. Any case-insensitive mapping works, which covers
                     both a plain dict and starlette's Headers.
        """
        self.debug_logger(f"Attempting to unpack token from headers {headers}")
        auth_str = headers.get(self.header_key)
        if auth_str is None:
            # A plain dict is case sensitive, unlike starlette's Headers, so fall back to
            # a scan rather than making callers match our capitalization.
            lowered = self.header_key.lower()
            auth_str = next(
                (value for key, value in headers.items() if key.lower() == lowered), None
            )
        self.debug_logger(f"Got {auth_str} using header key {self.header_key}")
        AuthenticationError.require_condition(
            auth_str,
            f"Could not find auth header at {self.header_key}",
        )
        auth_str = str(auth_str)

        self.debug_logger("Attempting to get authorization scheme")
        scheme, _, token = auth_str.partition(" ")
        token = token.strip()
        AuthenticationError.require_condition(
            scheme and token,
            f"Could not extract scheme ('{self.auth_scheme}') from token '{token}'",
        )
        AuthenticationError.require_condition(
            scheme.lower() == self.auth_scheme,
            f"Invalid auth scheme '{scheme}': expected '{self.auth_scheme}'",
        )
        return token

    def extract_token_payload(self, headers: Mapping[str, str]) -> TokenPayload:
        """
        Retrieve a token from request headers and decode it into a TokenPayload.

        Args:
            headers: The headers to read the token from.
        """
        token = self.unpack_token_from_header(headers)
        issuer = self.openid_config.issuer if self.verify_issuer else None

        if self.ignore_audience and self.audience is None:
            self.debug_logger(
                "Bypassing audience verification (ignore_audience=True, audience=None)"
            )
            return self.token_decoder.decode(
                token,
                issuer=issuer,
                options={"verify_aud": False},
            )

        return self.token_decoder.decode(token, audience=self.audience, issuer=issuer)
