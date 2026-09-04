"""
Pydantic models for the data armasec exchanges with an OIDC provider.

These are close to upstream armasec's own model definitions. Unlike upstream, `JWK`
requires only `kty` and `kid`: the members a particular key type needs, such as `n` and
`e` for RSA or `crv`, `x` and `y` for EC, are validated later by `armasec_lite.jwt`, once
the algorithm in use is known. Requiring RSA-only fields here, as upstream does, makes a
provider that serves an EC or OKP key fail to parse its entire JWKS document.
"""

from __future__ import annotations

from collections.abc import Callable
from enum import Enum
from typing import Any
from urllib.parse import urlparse

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, ValidationInfo, field_validator


class PermissionMode(str, Enum):
    """
    How a route's required scopes are matched against a token's permissions.

    Attributes:
        ALL:  Require every listed permission.
        SOME: Require at least one of the listed permissions.
    """

    ALL = "ALL"
    SOME = "SOME"


class JWK(BaseModel):
    """
    One JSON Web Key from an OIDC provider's JWKS document.

    Only `kty` and `kid` are required. The members a particular key type needs are
    validated at use time by `armasec_lite.jwt`, since which ones are required depends
    on the algorithm. Unknown members are kept on the model directly, via
    `extra="allow"`.

    Attributes:
        kty: The key type: RSA, EC, OKP or oct.
        kid: The key id, matched against a token's `kid` header.
        alg: The algorithm the key is intended for.
        n:   RSA modulus, base64url encoded.
        e:   RSA exponent, base64url encoded.
        crv: EC or OKP curve name.
        x:   EC x coordinate or OKP public key, base64url encoded.
        y:   EC y coordinate, base64url encoded.
        k:   Symmetric key material, base64url encoded.
        use: The intended use of the key.
        x5c: The X.509 certificate chain.
        x5t: The X.509 certificate SHA-1 thumbprint.
    """

    model_config = ConfigDict(extra="allow")

    kty: str
    kid: str
    alg: str | None = None
    n: str | None = None
    e: str | None = None
    crv: str | None = None
    x: str | None = None
    y: str | None = None
    k: str | None = None
    use: str | None = None
    x5c: list[str] | None = None
    x5t: str | None = None


class JWKs(BaseModel):
    """
    The container object retrieved from an OIDC provider's JWKS endpoint.

    Attributes:
        keys: The JWKs contained within.
    """

    keys: list[JWK]


class OpenidConfig(BaseModel):
    """
    The subset of an openid-configuration document that armasec uses.

    `issuer` is compared against a token's `iss` claim by exact string equality in
    `TokenManager`, so it is kept as a plain `str` and validated without being rewritten:
    a normalized copy (say, one with a trailing slash appended) would no longer match
    what the provider actually published, and would reject every valid token from a
    provider that publishes a bare-host issuer. `jwks_uri` has no such constraint, since
    it is only ever fetched, never compared, so it is kept as `AnyHttpUrl` and pinned to
    https by default: it arrives inside a document fetched over the network and is then
    fetched in turn.

    Attributes:
        issuer:   The URL of the issuer of the tokens, preserved exactly as published.
        jwks_uri: The URI where JWKs can be found on the OpenID server.
    """

    model_config = ConfigDict(extra="allow")

    issuer: str
    jwks_uri: AnyHttpUrl

    @field_validator("issuer")
    @classmethod
    def _validate_issuer(cls, value: str) -> str:
        """
        Check that `issuer` is an absolute http or https URL with a host, unchanged.

        Uses `urlparse` rather than `AnyHttpUrl` specifically to avoid pydantic's URL
        normalization, since the value must survive byte-for-byte for later comparison
        against a token's `iss` claim.
        """
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"issuer has an unsupported scheme {parsed.scheme!r}: {value!r}")
        if not parsed.hostname:
            raise ValueError(f"issuer has no host: {value!r}")
        return value

    @field_validator("jwks_uri")
    @classmethod
    def _pin_jwks_uri_scheme(cls, value: AnyHttpUrl, info: ValidationInfo) -> AnyHttpUrl:
        """
        Reject an http `jwks_uri` unless the validation context says https is not required.

        Defaults to requiring https: forgetting to pass `context={"require_https": ...}`
        must fail closed, not silently accept a plaintext JWKS endpoint. The one caller
        that legitimately wants it off, `openid_config_loader.py` for a domain configured
        with `use_https=False`, passes `require_https=False` explicitly.
        """
        require_https = True
        if info.context is not None:
            require_https = info.context.get("require_https", True)
        if require_https and value.scheme != "https":
            raise ValueError(f"jwks_uri must use https: {value}")
        return value


class DomainConfig(BaseModel):
    """
    Configuration for one OIDC domain to authenticate tokens against.

    Attributes:
        domain:               The OIDC domain from which resources are loaded.
        audience:             Optional designation of the token audience.
        ignore_audience:      If true and audience is None, skip audience verification.
        algorithm:            The algorithm to use for decoding. Defaults to RS256.
        use_https:            If falsey, use http instead of https for provider URLs.
        verify_issuer:        Check the token's `iss` claim against the provider's
                              configured issuer. Defaults to True. Upstream armasec loads
                              the issuer and never checks it; set this False for exact
                              upstream behavior.
        match_keys:           Key/value pairs that must be present in a decoded token.
                              A mismatch raises 403.
        permission_extractor: Optional function that extracts permissions from the
                              decoded token when they are not a top level claim.
    """

    domain: str = ""
    audience: str | None = None
    ignore_audience: bool = False
    algorithm: str = "RS256"
    use_https: bool = True
    verify_issuer: bool = True
    match_keys: dict[str, Any] = {}
    permission_extractor: Callable[[dict[str, Any]], list[str]] | None = None
