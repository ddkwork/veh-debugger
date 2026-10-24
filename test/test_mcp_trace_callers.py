"""Profile a real synthetic function using the shared bounded MCP client."""
import ctypes
import os
from ctypes import wintypes

from build_paths import RELEASE
from mcp_test_client import McpClient


def check(result):
    assert "error" not in result and result.get("success", True), result
    return result


def main():
    client = McpClient()
    target = None
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    try:
        client.initialize("trace-callers-test")
        launched = check(client.tool("veh_launch", {
            "program": os.path.join(RELEASE, "test_target.exe"),
            "args": ["--interval", "10"], "stopOnEntry": True,
        }))
        target = kernel.OpenProcess(0x00100000, False, launched["pid"])
        assert target, ctypes.get_last_error()
        bp = check(client.tool("veh_set_function_breakpoint", {"name": "WorkFunction"}))
        stop = check(client.tool("veh_continue", {"wait": True, "timeout": 10}, timeout=15))
        assert stop.get("reason") == "breakpoint", stop
        check(client.tool("veh_remove_breakpoint", {"id": bp["id"]}))
        result = check(client.tool("veh_trace_callers", {
            "address": stop["address"], "duration_sec": 1,
        }))
        assert result["totalHits"] >= result["uniqueCallers"] > 0, result
        assert result["uniqueCallers"] == len(result["callers"]), result
        assert all(item["address"] and item["hitCount"] > 0 for item in result["callers"]), result
        assert result["durationMs"] == 1000 and result["durationSec"] == 1, result
        print("PASS callers, counts, duration aliases and notification-safe responses")
    finally:
        client.close()
        if target:
            try:
                assert kernel.WaitForSingleObject(target, 5000) == 0, "test target did not exit"
            finally:
                kernel.CloseHandle(target)


if __name__ == "__main__":
    main()
