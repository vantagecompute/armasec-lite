import pytest

from armasec_lite.pluggable import PluginManager, hookimpl


class Denied(Exception):
    """Locally defined stand-in for ArmasecError, used only to prove exceptions propagate."""


class _Sentinel:
    pass


def test_hookimpl_marks_a_function():
    @hookimpl
    def armasec_plugin_check():
        pass

    assert getattr(armasec_plugin_check, "_armasec_hookimpl", False) is True


def test_registered_hook_is_called():
    calls = []

    class Plugin:
        @hookimpl
        def armasec_plugin_check(self, token_payload):
            calls.append(token_payload)

    manager = PluginManager()
    manager.register(Plugin())
    manager.hook.armasec_plugin_check(request="r", token_payload="p", debug_logger=print)

    assert calls == ["p"]


def test_only_declared_keyword_arguments_are_passed():
    """
    pluggy passes an implementation only the arguments it declares. The documented
    example plugin declares just token_payload, so passing it request and debug_logger
    would be a TypeError.
    """
    seen = {}

    class Plugin:
        @hookimpl
        def armasec_plugin_check(self, request, token_payload):
            seen["request"] = request
            seen["token_payload"] = token_payload

    manager = PluginManager()
    manager.register(Plugin())
    manager.hook.armasec_plugin_check(request="r", token_payload="p", debug_logger=print)

    assert seen == {"request": "r", "token_payload": "p"}


def test_an_implementation_taking_kwargs_receives_everything():
    seen = {}

    class Plugin:
        @hookimpl
        def armasec_plugin_check(self, **kwargs):
            seen.update(kwargs)

    manager = PluginManager()
    manager.register(Plugin())
    manager.hook.armasec_plugin_check(request="r", token_payload="p", debug_logger=print)

    assert set(seen) == {"request", "token_payload", "debug_logger"}


def test_a_module_can_be_registered():
    import types

    module = types.ModuleType("fake_plugin")
    calls = []

    @hookimpl
    def armasec_plugin_check(token_payload):
        calls.append(token_payload)

    module.armasec_plugin_check = armasec_plugin_check

    manager = PluginManager()
    manager.register(module)
    manager.hook.armasec_plugin_check(request="r", token_payload="p", debug_logger=print)

    assert calls == ["p"]


def test_unmarked_callables_are_not_registered():
    calls = []

    class Plugin:
        def armasec_plugin_check(self, token_payload):
            calls.append(token_payload)

    manager = PluginManager()
    manager.register(Plugin())
    manager.hook.armasec_plugin_check(request="r", token_payload="p", debug_logger=print)

    assert calls == []


def test_exceptions_propagate_because_raising_is_how_a_plugin_denies():
    class Denier:
        @hookimpl
        def armasec_plugin_check(self, token_payload):
            raise Denied("denied")

    manager = PluginManager()
    manager.register(Denier())
    with pytest.raises(Denied, match="denied"):
        manager.hook.armasec_plugin_check(request="r", token_payload="p", debug_logger=print)


def test_hooks_are_called_in_lifo_order():
    order = []

    def _make(name):
        class Plugin:
            @hookimpl
            def armasec_plugin_check(self, token_payload):
                order.append(name)

        return Plugin()

    manager = PluginManager()
    manager.register(_make("first"))
    manager.register(_make("second"))
    manager.hook.armasec_plugin_check(request="r", token_payload="p", debug_logger=print)

    assert order == ["second", "first"]


def test_unregister_removes_a_plugin():
    calls = []

    class Plugin:
        @hookimpl
        def armasec_plugin_check(self, token_payload):
            calls.append(token_payload)

    plugin = Plugin()
    manager = PluginManager()
    manager.register(plugin)
    manager.unregister(plugin)
    manager.hook.armasec_plugin_check(request="r", token_payload="p", debug_logger=print)

    assert calls == []


def test_registering_the_same_plugin_twice_is_idempotent():
    calls = []

    class Plugin:
        @hookimpl
        def armasec_plugin_check(self, token_payload):
            calls.append(1)

    plugin = Plugin()
    manager = PluginManager()
    manager.register(plugin)
    manager.register(plugin)
    manager.hook.armasec_plugin_check(request="r", token_payload="p", debug_logger=print)

    assert calls == [1]


def test_no_plugins_is_a_no_op():
    PluginManager().hook.armasec_plugin_check(request="r", token_payload="p", debug_logger=print)
