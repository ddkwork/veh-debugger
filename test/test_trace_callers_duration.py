"""Caller trace duration compatibility through direct and nested MCP calls."""
import ctypes
import os
from ctypes import wintypes

import pytest

from build_paths import RELEASE
from mcp_test_client import McpClient


def check(result):
    assert "error" not in result and result.get("success", True), result
    return result


@pytest.fixture(scope="module")
def session():
    client = McpClient()
    target = None
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    try:
        client.initialize("trace-callers-duration-test")
        launch = check(client.tool("veh_launch", {
            "program": os.path.join(RELEASE, "test_target.exe"),
            "args": ["--interval", "10"], "stopOnEntry": True,
        }))
        # Retain the original handle; cleanup must not adopt a reused PID.
        target = kernel.OpenProcess(0x00100000, False, launch["pid"])
        assert target, ctypes.get_last_error()
        bp = check(client.tool("veh_set_function_breakpoint", {"name": "WorkFunction"}))
        stop = check(client.tool("veh_continue", {"wait": True, "timeout": 10}, timeout=15))
        assert stop.get("reason") == "breakpoint", stop
        check(client.tool("veh_remove_breakpoint", {"id": bp["id"]}))
        yield client, stop["address"]
    finally:
        client.close()
        assert client.proc.poll() is not None, "MCP server did not exit"
        if target:
            try:
                assert kernel.WaitForSingleObject(target, 5000) == 0, "test target did not exit"
            finally:
                kernel.CloseHandle(target)


@pytest.mark.parametrize("route", ["direct", "batch"])
@pytest.mark.parametrize("duration, milliseconds, seconds", [
    ({"duration_sec": 1}, 1000, 1),
    ({"duration_ms": 1500}, 1500, 1.5),
    ({"duration_sec": 3, "duration_ms": 250}, 250, 0.25),
])
def test_duration_compatibility(session, route, duration, milliseconds, seconds):
    client, address = session
    args = {"address": address, **duration}
    if route == "direct":
        result = check(client.tool("veh_trace_callers", args))
    else:
        batch = check(client.tool("veh_batch", {"steps": [
            {"tool": "veh_trace_callers", "args": args},
        ]}))
        assert batch["failed"] == 0, batch
        result = check(batch["results"][0]["result"])
    assert result["totalHits"] > 0, result
    assert result["uniqueCallers"] == len(result["callers"]) > 0, result
    assert result["durationMs"] == milliseconds, result
    assert result["durationSec"] == seconds, result
    if milliseconds % 1000 == 0:
        assert type(result["durationSec"]) is int, result
