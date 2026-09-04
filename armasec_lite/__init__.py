"""Injectable FastAPI auth via OIDC, built on the standard library."""

import importlib.metadata

__version__ = importlib.metadata.version("armasec-lite")

__all__ = ["__version__"]
