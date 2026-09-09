"""
Pydantic models for the data armasec exchanges with an OIDC provider.

Two of these describe documents fetched from the provider (`OpenidConfig` and `JWKs`, with
`JWK` inside it) and two describe how a consumer configures this library (`DomainConfig`
and `PermissionMode`). These are close to upstream armasec's own definitions, with three
deliberate departures, each of which looks like a mistake until you know why.

### `JWK` requires only `kty` and `kid`

The members a particular key type needs, such as `n` and `e` for RSA or `crv`, `x` and `y`
for EC, are validated later by `armasec_lite.jwt`, once the algorithm in use is known.
Upstream requires the RSA members here, which means a provider serving an EC or OKP key
alongside its RSA keys fails to parse its entire JWKS document, and every token is
rejected. Validation is not skipped by moving it, only deferred to the point where the
requirement is actually known.

### `OpenidConfig.issuer` is a plain `str`, not `AnyHttpUrl`

`TokenManager` compares it against a token's `iss` claim by exact string equality, so the
value has to survive byte for byte. Pydantic's URL types normalize: `AnyHttpUrl` appends a
trailing slash to a bare-host URL, so a provider publishing `https://auth.example.com`
would be stored as `https://auth.example.com/` and would then match no token it ever
issued. The field is validated all the same, by `urlparse`, for an absolute http or https
URL with a host, and returned unchanged.

`jwks_uri` has no such constraint, since it is only ever fetched and never compared, so it
stays `AnyHttpUrl` and is additionally pinned to https by default. That pin fails closed:
the validator requires https unless a validation context explicitly says otherwise, so
forgetting to pass the context cannot silently accept a plaintext JWKS endpoint. The only
caller that legitimately turns it off is `openid_config_loader.py`, for a domain
configured with `use_https=False`.

### `DomainConfig.domain` is required and must be non-empty

Upstream defaults it to the empty string, which builds the discovery URL
`https:///.well-known/openid-configuration` and fails at request time with an error that
says nothing about the real mistake. Rejecting it at construction is worth the small
departure from upstream's signature.

### The constants

`SUPPORTED_ALGORITHMS` is what `DomainConfig.algorithm` is validated against. It is
duplicated from `armasec_lite.jwt` rather than imported: `jwt` imports `JWK` from this
module, so importing back the other way is a circular import. `tests/unit/test_schemas.py`
asserts the two sets are equal, so they cannot drift apart silently.
"""

from __future__ import annotations

from collections.abc import Callable, Collection
from enum import Enum
from typing import Any
from urllib.parse import urlparse

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, ValidationInfo, field_validator

#: The algorithms a `DomainConfig` will accept, duplicated from `armasec_lite.jwt` rather
#: than imported from it. `jwt` imports `JWK` from this module, so importing back the
#: other way is a circular import. `test_schemas.py` asserts the two sets are equal, so
#: they cannot drift apart silently.
SUPPORTED_ALGORITHMS: frozenset[str] = frozenset(
    {
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "ES512",
        "HS256",
        "HS384",
        "HS512",
        "EdDSA",
    }
)


class PermissionMode(str, Enum):
    """
    How a route's required scopes are matched against a token's permissions.

    A `str` subclass as well as an `Enum`, so the string values compare equal to the
    members and a consumer can pass "ALL" where the enum is expected.

    Attributes:
        ALL:  Require every listed permission.
        SOME: Require at least one of the listed permissions.
    """

    ALL = "ALL"
    SOME = "SOME"


class JWK(BaseModel):
    """
    One JSON Web Key from an OIDC provider's JWKS document.

    Only `kty` and `kid` are required, unlike upstream armasec, which requires the RSA
    members and therefore fails to parse a whole JWKS document that happens to contain an
    EC or OKP key. The members a particular key type needs are validated at use time by
    `armasec_lite.jwt`, since which ones are required depends on the algorithm rather than
    on anything knowable here. Unknown members are kept on the model directly, via
    `extra="allow"`.

    Every field below other than `kty` and `kid` is therefore optional at parse time and
    may still be mandatory in practice: `armasec_lite.jwt` raises `InvalidKeyError` naming
    the missing member when a key is actually used to verify a signature.

    `alg` is advisory only. It is never used to choose a verification algorithm; that
    comes from `DomainConfig.algorithm` by way of the caller's allowlist. Nor is `crv`
    used to choose an ECDSA curve, which comes from the algorithm name, so a substituted
    weaker curve in a hostile JWKS has no effect.

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

    A provider may publish several keys at once, which is normal during a key rotation:
    the new signing key appears alongside the old one so tokens already in the wild keep
    verifying. `TokenDecoder` selects among them by the token's `kid`.

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

        Args:
            value: The issuer as the provider published it.

        Returns:
            The same string, not a normalized copy. Returning anything else here would
            break issuer verification for providers that publish a bare-host issuer.

        Raises:
            ValueError: The scheme is not http or https, or there is no host. Pydantic
                turns this into a ValidationError at the model boundary, and the loader
                turns that into an `AuthenticationError`.
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

        Args:
            value: The parsed URL.
            info:  Pydantic's validation info, carrying the context the loader passed.

        Returns:
            The URL unchanged when it is acceptable.

        Raises:
            ValueError: The URL is http and the context did not say https is optional.
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

    `domain` is required and must be non-empty. Upstream defaults it to the empty string,
    which builds the discovery URL `https:///.well-known/openid-configuration` and fails
    at request time with an error that says nothing about the real mistake. Rejecting it
    at construction is worth the small departure from upstream's signature.

    `algorithm` is the whole allowlist for this domain, not a hint or a default. It
    becomes the single-element list `decode` checks a token's `alg` against, which is what
    makes the `alg: none` and algorithm-confusion defenses effective: a token asking for
    anything else is refused before a key is touched. Configure the one algorithm the
    provider actually signs with.

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
                              decoded token when they are not a top level claim. May
                              return any collection of strings; pydantic coerces the
                              result into `TokenPayload.permissions`, a set.
    """

    domain: str
    audience: str | None = None
    ignore_audience: bool = False
    algorithm: str = "RS256"
    use_https: bool = True
    verify_issuer: bool = True
    match_keys: dict[str, Any] = {}
    permission_extractor: Callable[[dict[str, Any]], Collection[str]] | None = None

    @field_validator("domain")
    @classmethod
    def _validate_domain(cls, value: str) -> str:
        """
        Reject an empty or whitespace-only domain.

        Without this the discovery URL becomes `https:///.well-known/openid-configuration`
        and the failure surfaces much later, as an opaque connection error.

        Args:
            value: The configured domain.

        Returns:
            The domain unchanged. Whitespace is not stripped, only rejected when it is all
            there is.

        Raises:
            ValueError: The domain is empty or whitespace only.
        """
        if not value.strip():
            raise ValueError("domain must not be empty")
        return value

    @field_validator("algorithm")
    @classmethod
    def _validate_algorithm(cls, value: str) -> str:
        """
        Reject an algorithm the jwt layer does not support.

        Otherwise a typo configures a route that refuses every token it is ever shown,
        with a message about the token rather than about the configuration.

        Args:
            value: The configured algorithm name.

        Returns:
            The algorithm unchanged.

        Raises:
            ValueError: The algorithm is not in `SUPPORTED_ALGORITHMS`. The message lists
                the accepted values, since the usual cause is a typo.
        """
        if value not in SUPPORTED_ALGORITHMS:
            raise ValueError(
                f"algorithm {value!r} is not supported; expected one of "
                f"{sorted(SUPPORTED_ALGORITHMS)}"
            )
        return value
