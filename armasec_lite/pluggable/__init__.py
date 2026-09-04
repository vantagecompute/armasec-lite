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
from typing import Any, NamedTuple

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
        for implementation, accepted in self._manager.dispatch_targets():
            if accepted is None:
                implementation(**kwargs)
            else:
                implementation(**{k: v for k, v in kwargs.items() if k in accepted})


def _accepted_parameters(func: Callable[..., Any]) -> frozenset[str] | None:
    """
    Name the keyword arguments a callable declares, or None if it takes `**kwargs`.

    Filtering the argument set is the one pluggy behavior armasec depends on: the
    documented example plugin declares only `token_payload`, so handing it `request` and
    `debug_logger` would be a TypeError rather than a working plugin. Computed once at
    registration, because the dispatch that uses it is the authenticated request path and
    `inspect.signature` is not cheap.

    Args:
        func: The implementation being registered.
    """
    parameters = inspect.signature(func).parameters
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in parameters.values()):
        return None
    return frozenset(parameters)


class _Registration(NamedTuple):
    """
    One registered plugin with its hook resolved.

    Attributes:
        plugin:         The registered module or object.
        implementation: Its marked hook, or None when it carries none.
        accepted:       The keyword arguments the hook declares, or None when it takes
                        `**kwargs` and should receive everything. Only meaningful when
                        `implementation` is not None.
    """

    plugin: Any
    implementation: Callable[..., Any] | None
    accepted: frozenset[str] | None


def _find_implementation(plugin: Any) -> Callable[..., Any] | None:
    """
    Return a plugin's marked hook implementation, or None.

    Args:
        plugin: The module or object to inspect.
    """
    candidate = getattr(plugin, HOOK_NAME, None)
    if candidate is None or not callable(candidate):
        return None
    # A bound method carries the marker on its underlying function.
    target = getattr(candidate, "__func__", candidate)
    return candidate if getattr(target, _MARKER, False) else None


class PluginManager:
    """
    Holds registered plugins and dispatches hooks to them.
    """

    def __init__(self) -> None:
        """Create an empty manager."""
        self._registrations: list[_Registration] = []
        self.hook = _HookRelay(self)

    def register(self, plugin: Any, name: str | None = None) -> None:
        """
        Register a module or object carrying marked hook implementations.

        The hook and its accepted argument names are resolved here, once, rather than on
        every dispatch. Dispatch happens on the authenticated request path.

        Registering the same plugin twice is a no-op, so an import executed more than once
        does not double every check.

        Args:
            plugin: The module or object to register.
            name:   Accepted for compatibility with pluggy's signature. Unused.
        """
        if any(registration.plugin == plugin for registration in self._registrations):
            return
        implementation = _find_implementation(plugin)
        accepted = None if implementation is None else _accepted_parameters(implementation)
        self._registrations.append(_Registration(plugin, implementation, accepted))

    def unregister(self, plugin: Any) -> None:
        """
        Remove a previously registered plugin.

        Args:
            plugin: The module or object to remove.
        """
        self._registrations = [
            registration for registration in self._registrations if registration.plugin != plugin
        ]

    def get_plugins(self) -> list[Any]:
        """Return the registered plugins, in registration order."""
        return [registration.plugin for registration in self._registrations]

    def implementations(self) -> list[Callable[..., Any]]:
        """
        Collect every marked implementation, most recently registered first.
        """
        return [target for target, _ in self.dispatch_targets()]

    def dispatch_targets(self) -> list[tuple[Callable[..., Any], frozenset[str] | None]]:
        """
        Pair every marked implementation with its accepted argument names, LIFO.
        """
        return [
            (registration.implementation, registration.accepted)
            for registration in reversed(self._registrations)
            if registration.implementation is not None
        ]

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
