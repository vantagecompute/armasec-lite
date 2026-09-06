"""
Extracts a bearer token from request headers and decodes it.

The thin layer between `TokenSecurity`, which holds one manager per configured domain, and
`TokenDecoder`, which does the verification. It owns two things the decoder does not: how a
token is found in a request's headers, and which claim constraints the decoder is asked to
enforce.

### Header handling

The header name and scheme are class attributes, `header_key` ("Authorization") and
`auth_scheme` ("bearer"), so they are shared by every instance and are what
`TokenSecurity` advertises in the OpenAPI document. The scheme is compared
case-insensitively, since "Bearer" and "bearer" are both correct.

The lookup falls back to a case-insensitive scan when a direct `get` misses. Starlette's
`Headers` is already case-insensitive, but a plain `dict` is not, and this method is called
directly by tests and by consumers with dicts they built themselves. Making them match our
capitalization would be a needless trap.

### Issuer and audience

`verify_issuer` defaults to True, which is a deliberate departure: upstream armasec loads
the provider's issuer and then never checks a token against it. Pass False for exact
upstream behavior. The comparison is exact string equality, which is why
`OpenidConfig.issuer` is stored unnormalized.

Audience verification is skipped in two cases, and they are worth separating. The explicit
one is `ignore_audience=True` with no audience configured, which turns `verify_aud` off by
name. The implicit one is the `DomainConfig` default, `audience=None` with
`ignore_audience=False`: `verify_aud` stays on, but `jwt.decode` only checks `aud` when an
audience was actually passed, so nothing is compared.

That second case is the operator-visible one. A domain with no configured audience performs
no audience check at all, so in a multi-domain setup a token the same issuer minted for a
different API is accepted here. This matches upstream armasec, and configuring `audience`
is what closes it.
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

    One manager exists per configured domain. `TokenSecurity` tries each in turn until one
    decodes the request's token.

    `auth_scheme` and `header_key` are class attributes rather than instance ones, so
    `TokenSecurity` can read `TokenManager.header_key` without an instance when building
    the OpenAPI security scheme.

    Attributes:
        auth_scheme:             The scheme expected in the header, "bearer". Compared
                                 case-insensitively. Class-level.
        header_key:              The header the token is read from, "Authorization".
                                 Class-level.
        openid_config:           The provider's configuration, used only for its issuer.
        token_decoder:           The decoder that verifies the token.
        audience:                The audience a token must carry, or None.
        ignore_audience:         Skip audience verification when `audience` is also None.
        verify_issuer:           Check the token's `iss` against the provider's issuer.
                                 True by default; upstream armasec never checked it.
        debug_logger:            A callable such as `logger.debug`, defaulting to `noop`.
        decode_options_override: Held for compatibility with upstream's signature. The
                                 decoder carries its own copy, which is the one that takes
                                 effect.
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
        Store the provider config, decoder and claim constraints. Nothing is fetched here.

        Args:
            openid_config:           The provider's configuration, used for the issuer.
            token_decoder:           The decoder used to verify jwts.
            audience:                An optional audience to check in decoded tokens.
            ignore_audience:         If true and audience is None, skip audience checks.
            verify_issuer:           Check the token's `iss` against the provider's issuer.
                                     Upstream armasec never performed this check; pass
                                     False for exact upstream behavior.
            debug_logger:            A callable such as `logger.debug`.
            decode_options_override: Accepted for compatibility with upstream armasec's
                                     signature and stored, but never consulted. The
                                     decoder holds its own, which is the one that takes
                                     effect; pass options to `TokenDecoder` instead.
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

        Nothing is verified here. The return value is an attacker-supplied string that has
        been through no cryptographic check whatsoever; it is only shaped like a token.

        Args:
            headers: The headers to read. Any mapping works: a case-insensitive one such
                     as starlette's `Headers` hits directly, and a plain `dict` falls back
                     to a case-insensitive scan rather than requiring the caller to match
                     our capitalization.

        Returns:
            The token, with the scheme prefix stripped and surrounding whitespace removed.

        Raises:
            AuthenticationError: The header is absent, has no scheme or no token after it,
                or names a scheme other than "bearer". Maps to 401. This is the failure an
                unauthenticated request produces, so it is by far the most common error in
                the library and is not on its own a sign of an attack.
        """
        if self.debug_logger is not noop:
            self.debug_logger(f"Attempting to unpack token from headers {headers}")
        auth_str = headers.get(self.header_key)
        if auth_str is None:
            # A plain dict is case sensitive, unlike starlette's Headers, so fall back to
            # a scan rather than making callers match our capitalization.
            lowered = self.header_key.lower()
            auth_str = next(
                (value for key, value in headers.items() if key.lower() == lowered), None
            )
        if self.debug_logger is not noop:
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

        The one method `TokenSecurity` calls per manager. It decides which claim
        constraints the decoder enforces: the provider's issuer when `verify_issuer` is
        set, and the configured audience unless `ignore_audience` is set with no audience
        configured, in which case `verify_aud` is turned off explicitly.

        Args:
            headers: The headers to read the token from.

        Returns:
            The verified payload.

        Raises:
            AuthenticationError: The header is missing or malformed, the token does not
                verify, or a claim check failed. Includes the subclasses from
                `armasec_lite.jwt`, which name the specific failure. Maps to 401.
            PayloadMappingError: A configured `permission_extractor` did not match the
                decoded token. Maps to 500, not 401: the token is fine, the server's
                configuration is not.
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
