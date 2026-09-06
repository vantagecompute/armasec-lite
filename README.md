<div align="center">
<a href="https://www.vantagecompute.ai/">
  <img src="https://vantage-compute-public-assets.s3.us-east-1.amazonaws.com/branding/vantage-logo-text-black-horz.png" alt="Vantage Compute Logo" width="100" style="margin-bottom: 0.5em;"/>
</a>
</div>

<div align="center">

# armasec-lite

Injectable FastAPI auth via OIDC, with three dependencies instead of ten.

[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12+-blue.svg)](https://python.org)
[![PyPI](https://img.shields.io/pypi/v/armasec-lite.svg)](https://pypi.org/project/armasec-lite/)
![Build Status](https://img.shields.io/github/actions/workflow/status/vantagecompute/armasec-lite/release.yml?branch=main&label=build&logo=github&style=plastic)
![GitHub Issues](https://img.shields.io/github/issues/vantagecompute/armasec-lite?label=issues&logo=github&style=plastic)
![Pull Requests](https://img.shields.io/github/issues-pr/vantagecompute/armasec-lite?label=pull-requests&logo=github&style=plastic)
![GitHub Contributors](https://img.shields.io/github/contributors/vantagecompute/armasec-lite?logo=github&style=plastic)

</div>

`armasec-lite` validates bearer tokens against your identity provider's JWKS, checks
scopes and issuer/audience claims, and guards a route with a single `Depends()`. It is a
dependency-minimal reimplementation of
[armasec](https://github.com/omnivector-solutions/armasec) 3.x with the same public API,
built almost entirely on the standard library. Runtime dependencies are `fastapi`,
`cryptography` and `pydantic`.

## Install

```bash
uv add armasec-lite
```

The pytest fixtures, including the mock OIDC provider, live behind an extra:

```bash
uv add "armasec-lite[test]"
```

## Usage

```python
"""Secure a single route against one OIDC domain."""

import os

from armasec_lite import Armasec
from fastapi import Depends, FastAPI

app = FastAPI()
armasec = Armasec(
    domain=os.environ.get("ARMASEC_DOMAIN"),
    audience=os.environ.get("ARMASEC_AUDIENCE"),
)


@app.get("/stuff", dependencies=[Depends(armasec.lockdown("read:stuff"))])
async def check_access():
    return {"message": "Successfully authenticated!"}
```

Runnable variants, including multiple domains, `match_keys`, permission extractors and the
plugin system, are in [`examples/`](examples/).

## Documentation

[docs.vantagecompute.ai/developer/armasec-lite](https://docs.vantagecompute.ai/developer/armasec-lite/)

- [Installation](https://docs.vantagecompute.ai/developer/armasec-lite/installation)
- [Quickstart](https://docs.vantagecompute.ai/developer/armasec-lite/quickstart)
- [Migrating from armasec](https://docs.vantagecompute.ai/developer/armasec-lite/migration)
  covers every behavior difference from upstream 3.x, and what each one requires of you.
- [Security](https://docs.vantagecompute.ai/developer/armasec-lite/security/) covers the
  JWT verification order, the threat model, and what the attack suite defends.
- [Architecture](https://docs.vantagecompute.ai/developer/armasec-lite/architecture/)
  covers the request lifecycle, the caching model and the threading model.
- [API Reference](https://docs.vantagecompute.ai/developer/armasec-lite/api-reference/)

## License

MIT. See [LICENSE](LICENSE).
