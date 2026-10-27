"""DAP must report backend thread failures without inventing a thread."""
from pathlib import Path

from build_paths import RELEASE
from dap_test_client import DapClient


def run():
    adapter = Path(RELEASE) / "veh-debug-adapter.exe"
    client = DapClient(str(adapter))
    try:
        client.initialize()
        response = client.request("threads", timeout=5)
        assert response["success"] is False, response
        assert response["message"] == "GetThreads IPC failed", response
        assert not response.get("body", {}).get("threads"), response
        print("PASS DAP threads refuses disconnected backend without a synthetic thread")
    finally:
        client.close(terminate_debuggee=False)


if __name__ == "__main__":
    run()
