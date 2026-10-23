"""A fifth data breakpoint on the VEH backend says the debug registers are all used.

Run from the repository root: py -3 test/test_data_bp_slots.py
"""
import os
import sys

from build_paths import RELEASE
from mcp_test_client import McpClient

MCP_EXE = os.path.join(RELEASE, "veh-mcp-server.exe")
TARGET = os.path.join(RELEASE, "test_target.exe")


def main() -> int:
    c = McpClient(MCP_EXE)
    try:
        c.initialize()
        launched = c.tool("veh_launch", {"program": TARGET, "stopOnEntry": True}, 30)
        assert launched.get("success"), launched
        base = int(launched["mainModule"]["baseAddress"], 16) if "mainModule" in launched else \
            int(next(m for m in c.tool("veh_modules")["modules"] if m["name"].lower() == "test_target.exe")["baseAddress"], 16)
        results = [c.tool("veh_set_data_breakpoint", {"address": hex(base + 0x100 + i * 8), "size": 8, "type": "write"})
                   for i in range(5)]
        set_ok = all(r.get("id") or r.get("success") for r in results[:4])
        error = results[4].get("error", "")
        ok = set_ok and "no free slot" in error
        print(f"{'ok  ' if ok else 'FAIL'} fifth data breakpoint: {error!r}")
        c.tool("veh_terminate", {"exitCode": 0})
    finally:
        c.close()
    print(f"Results: {int(ok)} passed, {int(not ok)} failed")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
