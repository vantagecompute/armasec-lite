"""Accept tokens issued by either of two OIDC domains."""

import os

from fastapi import Depends, FastAPI

from armasec_lite import Armasec
from armasec_lite.schemas import DomainConfig

app = FastAPI()
armasec = Armasec(
    domain_configs=[
        DomainConfig(
            domain=os.environ.get("ARMASEC_DOMAIN_1", ""),
            audience=os.environ.get("ARMASEC_AUDIENCE_1"),
        ),
        DomainConfig(
            domain=os.environ.get("ARMASEC_DOMAIN_2", ""),
            audience=os.environ.get("ARMASEC_AUDIENCE_2"),
        ),
    ],
    debug_exceptions=True,
)


@app.get("/stuff", dependencies=[Depends(armasec.lockdown("read:stuff"))])
async def check_access():
    return {"message": "Successfully authenticated!"}
