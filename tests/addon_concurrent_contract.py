"""Black-box observations shared by the reference and local concurrent tests."""

import asyncio
import contextvars
import inspect
import threading


HOOK_NAMES = (
    "add_log", "client_connected", "client_disconnected", "configure", "dns_error",
    "dns_request", "dns_response", "done", "error", "http_connect",
    "http_connect_error", "http_connect_upstream", "http_connected", "load",
    "next_layer", "quic_start_client", "quic_start_server", "request",
    "requestheaders", "response", "responseheaders", "running", "server_connect",
    "server_connect_error", "server_connected", "server_disconnected", "tcp_end",
    "tcp_error", "tcp_message", "tcp_start", "tls_clienthello",
    "tls_established_client", "tls_established_server", "tls_failed_client",
    "tls_failed_server", "tls_start_client", "tls_start_server", "udp_end",
    "udp_error", "udp_message", "udp_start", "update", "websocket_end",
    "websocket_message", "websocket_start",
)


def outcome(operation):
    try:
        value = operation()
    except Exception as error:
        return {
            "ok": False,
            "type": type(error).__name__,
            "message": str(error),
        }
    return {
        "ok": True,
        "type": type(value).__name__,
    }


def collect_surface(script_module, implementation_module):
    def callback():
        return None

    accepted_hooks = []
    rejection_mismatches = []
    for name in HOOK_NAMES:
        callback.__name__ = name
        result = outcome(lambda: script_module.concurrent(callback))
        if result["ok"]:
            accepted_hooks.append(name)
            continue
        expected = {
            "ok": False,
            "type": "NotImplementedError",
            "message": f"Concurrent decorator not supported for '{name}' method.",
        }
        if result != expected:
            rejection_mismatches.append({
                "hook": name,
                "actual": result,
            })

    def running(value):
        return value

    wrapper = script_module.concurrent(running)
    return {
        "package_has_path": hasattr(script_module, "__path__"),
        "package_all_type": type(script_module.__all__).__name__,
        "package_all": list(script_module.__all__),
        "same_function": script_module.concurrent is implementation_module.concurrent,
        "implementation_has_all": hasattr(implementation_module, "__all__"),
        "function_module": script_module.concurrent.__module__,
        "noncallable": {
            "none": outcome(lambda: script_module.concurrent(None)),
            "integer": outcome(lambda: script_module.concurrent(1)),
            "lambda": outcome(lambda: script_module.concurrent(lambda: None)),
        },
        "accepted_hooks": accepted_hooks,
        "rejection_mismatches": rejection_mismatches,
        "wrapper": {
            "name": wrapper.__name__,
            "qualname": wrapper.__qualname__,
            "module": wrapper.__module__,
            "doc": wrapper.__doc__,
            "annotations": wrapper.__annotations__,
            "attributes": wrapper.__dict__,
            "signature": str(inspect.signature(wrapper)),
            "is_coroutine_function": inspect.iscoroutinefunction(wrapper),
        },
    }


async def collect_execution(concurrent):
    marker = contextvars.ContextVar("concurrent_contract", default="missing")
    caller_thread = threading.get_ident()
    events = []

    def running(value):
        events.append({
            "kind": "sync",
            "value": value,
            "different_thread": threading.get_ident() != caller_thread,
            "context": marker.get(),
        })
        marker.set("sync callback")
        return "ignored sync result"

    async def done(value):
        events.append({
            "kind": "async",
            "value": value,
            "different_thread": threading.get_ident() != caller_thread,
            "context": marker.get(),
            "has_running_loop": asyncio.get_running_loop() is not None,
        })
        marker.set("async callback")
        return "ignored async result"

    def update(_flows):
        events.append({
            "kind": "following sync",
            "different_thread": threading.get_ident() != caller_thread,
            "context": marker.get(),
        })

    def update_failure(_flows):
        raise RuntimeError("concurrent failure")

    update_failure.__name__ = "update"

    marker.set("caller")
    sync_result = await concurrent(running)("one")
    async_result = await concurrent(done)("two")
    following_result = await concurrent(update)(())

    try:
        await concurrent(update_failure)(())
    except Exception as error:
        failure = {
            "type": type(error).__name__,
            "message": str(error),
        }
    else:
        failure = None

    wrapper = concurrent(running)
    keyword_failure = outcome(lambda: wrapper(value="three"))
    return {
        "events": events,
        "sync_result": sync_result,
        "async_result": async_result,
        "following_result": following_result,
        "failure": failure,
        "keyword_failure": keyword_failure,
    }


def collect(script_module, implementation_module):
    return {
        "surface": collect_surface(script_module, implementation_module),
        "execution": asyncio.run(collect_execution(script_module.concurrent)),
    }
