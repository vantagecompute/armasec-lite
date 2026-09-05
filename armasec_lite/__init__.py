"""
Injectable FastAPI auth via OIDC, built on the standard library.

A dependency-minimal reimplementation of armasec. The public API matches upstream, with
three documented differences: the import name is `armasec_lite`,
`DomainConfig.verify_issuer` defaults to True, and `TokenDecoder` accepts an optional
`jwks_refresher`.
"""

import importlib.metadata

from armasec_lite.armasec import Armasec
from armasec_lite.openid_config_loader import OpenidConfigLoader
from armasec_lite.schemas import DomainConfig, PermissionMode
from armasec_lite.token_decoder import TokenDecoder, extract_keycloak_permissions
from armasec_lite.token_manager import TokenManager
from armasec_lite.token_payload import TokenPayload
from armasec_lite.token_security import TokenSecurity

__version__ = importlib.metadata.version("armasec-lite")

__all__ = [
    "Armasec",
    "DomainConfig",
    "OpenidConfigLoader",
    "PermissionMode",
    "TokenDecoder",
    "TokenManager",
    "TokenPayload",
    "TokenSecurity",
    "__version__",
    "extract_keycloak_permissions",
]
