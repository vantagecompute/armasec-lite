"""
The decoded contents of a JWT, in the shape armasec's consumers expect.

`TokenPayload` is what `TokenSecurity` returns, so it is the object a route handler
actually receives from its dependency. Everything else in the library exists to produce
one, and it is only ever constructed after a signature has verified: a `TokenPayload` in
hand means the claims on it came from the provider.

## `extra="allow"` is load-bearing

The five declared fields are the ones armasec itself uses. Every other claim in the token
stays reachable as an attribute, because `extra="allow"` puts unknown members on the model
directly. Two features depend on that and would silently stop working without it:
`DomainConfig.match_keys`, which reads arbitrary claims off the payload with `getattr`, and
plugin checks, which are handed the whole payload precisely so they can look at claims this
library knows nothing about.

The consequence worth keeping in mind is that an attribute that is present on one
provider's tokens may be absent on another's, and the model will not tell you in advance.
Read unknown claims with `getattr(payload, name, default)`.

## Aliases

`expire` and `client_id` accept two source names each, via `AliasChoices`: the registered
claim (`exp`, `azp`) and the friendlier name armasec's own API has always used. So a token
is read by its standard claim names while consumer code keeps the names it was written
against.

`to_dict` produces the flat dictionary upstream armasec's `to_dict` produced, with `expire`
back as an integer `exp`. It is a compatibility shim for migrating consumers, not the
preferred way to read a payload, and it drops every extra claim.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import AliasChoices, BaseModel, ConfigDict, Field


class TokenPayload(BaseModel):
    """A convenience class for accessing parts of a decoded jwt.

    Claims that are not declared fields remain reachable as attributes, because
    `extra="allow"` puts unknown members on the model directly. `match_keys` and
    plugin checks depend on this to read arbitrary claims off the token payload.

    Only `sub` is required. A provider that does not issue it produces a validation
    failure, which `TokenDecoder` reports as a `PayloadMappingError` (500) rather than a
    401, since the token itself verified.

    Attributes:
        sub:            The "sub" claim: the subject, meaning the authenticated principal.
                        The only required field.
        permissions:    The permissions the token grants, checked against a route's
                        scopes. Read from a top level `permissions` claim, or produced by
                        a `permission_extractor` for providers that nest them. Defaults to
                        empty, so a token with no permissions authenticates but authorizes
                        nothing.
        expire:         The "exp" (or "expire") claim, as a datetime. Informational here:
                        expiry was already enforced during decoding, so a payload in hand
                        is not expired.
        client_id:      The "azp" (or "client_id") claim: the OAuth client the token was
                        issued to, which is not the same thing as the user in `sub`.
        original_token: The compact token this payload was decoded from, so a consumer can
                        forward the caller's credential to a downstream service. Set by
                        `TokenDecoder`, and it wins over any `original_token` claim the
                        token itself carried.
    """

    sub: str
    permissions: list[str] = Field(default_factory=list)
    expire: datetime | None = Field(None, validation_alias=AliasChoices("exp", "expire"))
    client_id: str | None = Field(None, validation_alias=AliasChoices("azp", "client_id"))
    original_token: str | None = None

    model_config = ConfigDict(extra="allow")

    def to_dict(self) -> dict[str, Any]:
        """
        Convert to the flat dictionary shape upstream armasec's `to_dict` produced.

        A compatibility shim for consumers migrating from armasec 3.x. It is lossy on
        purpose, reproducing exactly the four keys upstream emitted: `original_token` and
        every extra claim `extra="allow"` kept are dropped, and `expire` becomes an integer
        `exp` again. Prefer reading attributes off the model directly.

        Returns:
            A dictionary with `sub`, `permissions`, `exp` and `client_id`. `exp` is None
            when the token carried no expiry.
        """
        return {
            "sub": self.sub,
            "permissions": self.permissions,
            "exp": int(self.expire.timestamp()) if self.expire is not None else None,
            "client_id": self.client_id,
        }
