"""Add a custom authorization check through the plugin system."""

import logging
import os
import sys

from fastapi import Depends, FastAPI
from pydantic import BaseModel

from armasec_lite import Armasec, TokenPayload
from armasec_lite.exceptions import ArmasecError
from armasec_lite.pluggable import hookimpl, plugin_manager

logger = logging.getLogger(__name__)

# Local data store of "subscribers" for this demo.
subscribers: set[str] = set()


class Subscriber(BaseModel):
    email: str


class PluginError(ArmasecError):
    """Raised when the authenticated user is not a subscriber."""

    status_code = 402
    detail = "User is not subscribed."


@hookimpl
def armasec_plugin_check(token_payload: TokenPayload):
    """Reject any token whose email is not in the subscriber set."""
    logger.debug("Applying check from example plugin")
    PluginError.require_condition(
        getattr(token_payload, "email", None) in subscribers,
        "User is not subscribed!",
    )


plugin_manager.register(sys.modules[__name__])


app = FastAPI()
armasec = Armasec(
    domain=os.environ.get("ARMASEC_DOMAIN"),
    audience=os.environ.get("ARMASEC_AUDIENCE"),
    use_https=False,
    debug_logger=logger.debug,
)


@app.get("/stuff", dependencies=[Depends(armasec.lockdown("read:stuff"))])
async def check_access():
    return {"message": "Successfully authenticated!"}


@app.post("/stuff", dependencies=[Depends(armasec.lockdown("read:stuff", skip_plugins=True))])
async def add_subscriber(subscriber: Subscriber):
    subscribers.add(subscriber.email)
    return {"message": f"Added subscriber {subscriber.email}!"}
