"""
A small plugin system, replacing pluggy.

Only one hook exists and only one dispatch strategy is needed, so the fifty lines here
cover what armasec used pluggy for: a marker decorator, registration by module or object,
discovery through entry points, and calling each implementation with just the arguments
it declares.

## Writing a plugin

Mark a function named `armasec_plugin_check` with `@hookimpl` and advertise its module
under the `armasec` entry point group. `plugin_manager.load_entry_points()` runs at import
of this package, so an installed plugin is registered without the application doing
anything. Raising from the hook denies the request, and raising an `ArmasecError` subclass
chooses the status the client sees. See `armasec_lite.pluggable.hookspecs` for the full
signature.

## Each implementation receives only what it declares

This is the one pluggy behavior armasec actually depends on, and it is not a convenience.
The documented example plugin declares only `token_payload`, so handing it `request` and
`debug_logger` as well would be a `TypeError` rather than a working plugin. An
implementation taking `**kwargs` is handed everything instead.

The accepted names are computed once, at registration, and cached on the registration
record. Dispatch happens on the authenticated request path, and `inspect.signature` is not
cheap enough to call there.

## Other behaviors worth knowing

Implementations run most recently registered first, matching pluggy. Exceptions propagate
rather than being collected, because raising is how a plugin denies a request, and the
first refusal should end the check.

Registering the same plugin twice is a no-op, so a module imported more than once does not
double every check.

The module-level `plugin_manager` is the manager armasec dispatches through, and third
party plugins are discovered on it at import time. `PluginManager` is exported so a test
can build an isolated one.
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

    The armasec equivalent of pluggy's `@hookimpl`. Sets a private attribute on the
    function and returns it unchanged, so a marked function is still perfectly callable
    and directly testable.

    Marking alone does nothing: the function must also be named `armasec_plugin_check` and
    live on a registered module or object. `PluginManager.register` looks for that name and
    then checks for this marker.

    Args:
        func: The function to mark.

    Returns:
        The same function, marked.
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

        Called on the authenticated request path, once per request, unless the route was
        locked down with `skip_plugins`.

        Args:
            kwargs: The full argument set from the hook specification: `request`,
                    `token_payload` and `debug_logger`.

        Raises:
            Exception: Whatever an implementation raises, unchanged and immediately, so
                the first refusal ends the check and later implementations do not run.
                `TokenSecurity` translates it: an `ArmasecError` subclass supplies its own
                status, and anything else becomes a 403.
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

    Returns:
        The declared parameter names, or None when the callable takes `**kwargs` and
        should therefore receive every argument. Every parameter is counted, positional
        ones included, since the relay always calls by keyword.
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

    Returns:
        The callable named `HOOK_NAME` when it carries the `hookimpl` marker, otherwise
        None. A plugin with no hook registers successfully and is simply never dispatched
        to, which is what makes registering an arbitrary object harmless.
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

    The module-level `plugin_manager` is the instance armasec dispatches through, and is
    the one a plugin author's entry point ends up on. Constructing another is useful mainly
    in tests, where an isolated manager avoids touching whatever the process has discovered
    from installed packages.

    Attributes:
        hook: The relay. Call `manager.hook.armasec_plugin_check(...)` to dispatch, which
              is the pluggy-shaped API `TokenSecurity` uses.
    """

    def __init__(self) -> None:
        """
        Create an empty manager. Nothing is discovered until `load_entry_points` is called.
        """
        self._registrations: list[_Registration] = []
        self.hook = _HookRelay(self)

    def register(self, plugin: Any, name: str | None = None) -> None:
        """
        Register a module or object carrying marked hook implementations.

        The hook and its accepted argument names are resolved here, once, rather than on
        every dispatch. Dispatch happens on the authenticated request path.

        Registering the same plugin twice is a no-op, so an import executed more than once
        does not double every check.

        A plugin carrying no marked hook registers successfully and is simply never
        dispatched to, so registering an unrelated object is harmless rather than an error.

        Args:
            plugin: The module or object to register. A class instance works as well as a
                    module: a bound method carries the marker on its underlying function,
                    which `_find_implementation` accounts for.
            name:   Accepted for compatibility with pluggy's signature. Unused.

        Raises:
            TypeError: The marked hook's signature could not be inspected. In practice this
                means a C-implemented callable, which cannot be an armasec plugin.
        """
        if any(registration.plugin == plugin for registration in self._registrations):
            return
        implementation = _find_implementation(plugin)
        accepted = None if implementation is None else _accepted_parameters(implementation)
        self._registrations.append(_Registration(plugin, implementation, accepted))

    def unregister(self, plugin: Any) -> None:
        """
        Remove a previously registered plugin.

        Silent when the plugin was never registered. Matched by equality, the same as
        `register` deduplicates.

        Args:
            plugin: The module or object to remove.
        """
        self._registrations = [
            registration for registration in self._registrations if registration.plugin != plugin
        ]

    def get_plugins(self) -> list[Any]:
        """
        Return the registered plugins, in registration order.

        Includes plugins that carry no marked hook, since they were still registered.
        Registration order, not the LIFO dispatch order.

        Returns:
            A new list; mutating it does not change what is registered.
        """
        return [registration.plugin for registration in self._registrations]

    def implementations(self) -> list[Callable[..., Any]]:
        """
        Collect every marked implementation, most recently registered first.

        Returns:
            The hooks that will actually run, in the order they will run. Plugins carrying
            no marked hook are omitted.
        """
        return [target for target, _ in self.dispatch_targets()]

    def dispatch_targets(self) -> list[tuple[Callable[..., Any], frozenset[str] | None]]:
        """
        Pair every marked implementation with its accepted argument names, LIFO.

        What the relay iterates. The accepted names were computed at registration, so this
        does no inspection and is cheap enough for the request path.

        Returns:
            Pairs of hook and accepted parameter names, most recently registered first. A
            None in the second position means the hook takes `**kwargs` and should receive
            every argument.
        """
        return [
            (registration.implementation, registration.accepted)
            for registration in reversed(self._registrations)
            if registration.implementation is not None
        ]

    def load_entry_points(self, group: str = "armasec") -> None:
        """
        Register every plugin advertised under an entry point group.

        Called once on the module-level `plugin_manager` at import of this package, so an
        installed plugin is live without the application registering it. That also means
        each entry point's module is imported here, and an import-time failure in a plugin
        surfaces as a failure to import armasec.

        Args:
            group: The entry point group to search. Defaults to "armasec".

        Raises:
            Exception: Whatever loading an entry point raises, such as an `ImportError` for
                a plugin whose own dependencies are missing.
        """
        for entry_point in entry_points(group=group):
            self.register(entry_point.load())


#: The manager armasec dispatches through. Third party plugins are discovered at import.
plugin_manager = PluginManager()
plugin_manager.load_entry_points()

__all__ = ["PluginManager", "armasec_plugin_check", "hookimpl", "plugin_manager"]
