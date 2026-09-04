"""
A small plugin system, replacing pluggy.

Only one hook exists and only one dispatch strategy is needed, so the fifty lines here
cover what armasec used pluggy for: a marker decorator, registration by module or object,
discovery through entry points, and calling each implementation with just the arguments
it declares.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from importlib.metadata import entry_points
from typing import Any

from armasec_lite.pluggable.hookspecs import HOOK_NAME, armasec_plugin_check

#: Attribute set on a function by `hookimpl` to mark it as an implementation.
_MARKER = "_armasec_hookimpl"


def hookimpl(func: Callable[..., Any]) -> Callable[..., Any]:
    """
    Mark a function as an armasec hook implementation.

    Args:
        func: The function to mark.
    """
    setattr(func, _MARKER, True)
    return func


class _HookRelay:
    """
    Dispatches a hook call to every registered implementation.
    """

    def __init__(self, manager: PluginManager):
        """
        Bind the relay to its manager.

        Args:
            manager: The manager whose implementations should be called.
        """
        self._manager = manager

    def armasec_plugin_check(self, **kwargs: Any) -> None:
        """
        Call every registered `armasec_plugin_check` implementation.

        Implementations are called most recently registered first, matching pluggy, and
        each receives only the keyword arguments it declares. Exceptions propagate,
        because raising is how a plugin denies a request.

        Args:
            kwargs: The full argument set from the hook specification.
        """
        for implementation in self._manager.implementations():
            implementation(**_filter_kwargs(implementation, kwargs))


def _filter_kwargs(func: Callable[..., Any], kwargs: dict[str, Any]) -> dict[str, Any]:
    """
    Reduce a keyword argument set to what a callable actually declares.

    This is the one pluggy behavior armasec depends on. The documented example plugin
    declares only `token_payload`, so handing it `request` and `debug_logger` would be a
    TypeError rather than a working plugin.

    Args:
        func:   The implementation about to be called.
        kwargs: The full argument set.
    """
    signature = inspect.signature(func)
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in signature.parameters.values()):
        return kwargs
    return {name: value for name, value in kwargs.items() if name in signature.parameters}


class PluginManager:
    """
    Holds registered plugins and dispatches hooks to them.
    """

    def __init__(self) -> None:
        """Create an empty manager."""
        self._plugins: list[Any] = []
        self.hook = _HookRelay(self)

    def register(self, plugin: Any, name: str | None = None) -> None:
        """
        Register a module or object carrying marked hook implementations.

        Registering the same plugin twice is a no-op, so an import executed more than once
        does not double every check.

        Args:
            plugin: The module or object to register.
            name:   Accepted for compatibility with pluggy's signature. Unused.
        """
        if plugin not in self._plugins:
            self._plugins.append(plugin)

    def unregister(self, plugin: Any) -> None:
        """
        Remove a previously registered plugin.

        Args:
            plugin: The module or object to remove.
        """
        if plugin in self._plugins:
            self._plugins.remove(plugin)

    def get_plugins(self) -> list[Any]:
        """Return the registered plugins, in registration order."""
        return list(self._plugins)

    def implementations(self) -> list[Callable[..., Any]]:
        """
        Collect every marked implementation, most recently registered first.
        """
        found: list[Callable[..., Any]] = []
        for plugin in reversed(self._plugins):
            candidate = getattr(plugin, HOOK_NAME, None)
            if candidate is None or not callable(candidate):
                continue
            # A bound method carries the marker on its underlying function.
            target = getattr(candidate, "__func__", candidate)
            if getattr(target, _MARKER, False):
                found.append(candidate)
        return found

    def load_entry_points(self, group: str = "armasec") -> None:
        """
        Register every plugin advertised under an entry point group.

        Args:
            group: The entry point group to search. Defaults to "armasec".
        """
        for entry_point in entry_points(group=group):
            self.register(entry_point.load())


#: The manager armasec dispatches through. Third party plugins are discovered at import.
plugin_manager = PluginManager()
plugin_manager.load_entry_points()

__all__ = ["PluginManager", "armasec_plugin_check", "hookimpl", "plugin_manager"]
