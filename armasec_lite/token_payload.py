"""The decoded contents of a JWT, in the shape armasec's consumers expect."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import AliasChoices, BaseModel, ConfigDict, Field


class TokenPayload(BaseModel):
    """A convenience class for accessing parts of a decoded jwt.

    Claims that are not declared fields remain reachable as attributes, because
    `extra="allow"` puts unknown members on the model directly. `match_keys` and
    plugin checks depend on this to read arbitrary claims off the token payload.

    Attributes:
        sub:            The "sub" claim from a JWT.
        permissions:    The permissions claims extracted from a JWT.
        expire:         The "exp" (or "expire") claim, as a datetime.
        client_id:      The "azp" (or "client_id") claim from a JWT.
        original_token: The original compact token value.
    """

    sub: str
    permissions: list[str] = Field(default_factory=list)
    expire: datetime | None = Field(None, validation_alias=AliasChoices("exp", "expire"))
    client_id: str | None = Field(None, validation_alias=AliasChoices("azp", "client_id"))
    original_token: str | None = None

    model_config = ConfigDict(extra="allow")

    def to_dict(self) -> dict[str, Any]:
        """Convert to the flat dictionary shape upstream armasec's `to_dict` produced."""
        return {
            "sub": self.sub,
            "permissions": self.permissions,
            "exp": int(self.expire.timestamp()) if self.expire is not None else None,
            "client_id": self.client_id,
        }
