"""Secure a single route against one OIDC domain."""

import os

from fastapi import Depends, FastAPI

from armasec_lite import Armasec

app = FastAPI()
armasec = Armasec(
    domain=os.environ.get("ARMASEC_DOMAIN"),
    audience=os.environ.get("ARMASEC_AUDIENCE"),
)


@app.get("/stuff", dependencies=[Depends(armasec.lockdown("read:stuff"))])
async def check_access():
    return {"message": "Successfully authenticated!"}
