"""veh_batch runs the direct MCP tool implementations (single dispatch path)."""
import hashlib
import json
import os


import pytest
import time

from mcp_test_client import McpClient, ROOT
from build_paths import IS_X86


def _build_dir():
    return os.environ.get("VEH_TEST_BUILD_DIR", os.path.join(ROOT, "build"))


@pytest.fixture(scope="module")
def session():
    target = os.path.join(_build_dir(), "bin", "Release", "test_target.exe")
    with McpClient() as client:
        client.initialize("batch-unified-test")
        launched = client.tool("veh_launch", {"program": target, "stopOnEntry": True})
        assert launched.get("success"), launched
        bp = client.tool("veh_set_function_breakpoint", {"name": "WorkFunction"})
        assert bp.get("success"), bp
        stop = client.tool("veh_continue", {"threadId": 0, "wait": True, "timeout": 30}, timeout=40)
        assert stop.get("stopped"), stop
        client.tool("veh_remove_breakpoint", {"id": bp["id"]})
        yield client, stop["threadId"]


def _steps(client, steps):
    report = client.tool("veh_batch", {"steps": steps}, timeout=60)
    return [entry["result"] for entry in report["results"]]


def test_batch_can_launch_then_inspect_without_a_prior_session():
    target = os.path.join(_build_dir(), "bin", "Release", "test_target.exe")
    with McpClient() as client:
        client.initialize("batch-launch-test")
        try:
            misplaced = client.tool("veh_batch", {"steps": [
                {"tool": "veh_modules", "args": {}},
                {"tool": "veh_launch", "args": {"program": target}},
            ]})
            assert "first-step" in misplaced["error"]
            repeated = client.tool("veh_batch", {
                "inputs": [1],
                "steps": [{"tool": "veh_launch", "args": {"program": target}}],
            })
            assert "cannot be repeated" in repeated["error"]
            report = client.tool("veh_batch", {"steps": [
                {"tool": "veh_launch", "args": {"program": target, "stopOnEntry": True},
                 "result_fields": ["success", "pid", "addressBits", "mainThreadId"]},
                {"tool": "veh_modules", "args": {}},
            ]})
            launch, modules = [entry["result"] for entry in report["results"]]
            assert launch["success"] is True and launch["pid"] > 0
            assert launch["addressBits"] == (32 if IS_X86 else 64), launch
            assert launch["mainThreadId"] > 0, launch
            threads = client.tool("veh_threads")
            assert launch["mainThreadId"] in [thread["id"] for thread in threads["threads"]], (launch, threads)
            assert modules["modules"]
        finally:
            client.tool("veh_terminate")


def test_step_waits_for_completion(session):
    client, tid = session
    ip_key = None
    for _ in range(5):
        step, regs = _steps(client, [
            {"tool": "veh_step_in", "args": {"threadId": tid}},
            {"tool": "veh_registers", "args": {"threadId": tid}},
        ])
        assert step.get("success"), step
        ip_key = ip_key or ("rip" if "rip" in regs["registers"] else "eip")
        # Direct step semantics: the step reports the landed IP and registers agree.
        assert int(step["instructionPointer"], 16) == int(regs["registers"][ip_key], 16)


def test_register_fields_filter(session):
    client, tid = session
    is32 = client.tool("veh_registers", {"threadId": tid})["registers"]["is32bit"]
    fields = ["esp", "eip"] if is32 else ["rsp", "rip"]
    direct = client.tool("veh_registers", {"threadId": tid, "fields": fields})
    (batched,) = _steps(client, [
        {"tool": "veh_registers", "args": {"threadId": tid, "fields": fields}},
    ])
    assert set(direct["registers"]) == set(batched["registers"]) == {*fields, "is32bit"}


def test_result_fields_keep_full_reference_values(session):
    client, tid = session
    registers = client.tool("veh_registers", {"threadId": tid})["registers"]
    ip_key = "eip" if registers["is32bit"] else "rip"
    report = client.tool("veh_batch", {"steps": [
        {"tool": "veh_registers", "args": {"threadId": tid},
         "result_fields": [f"registers.{ip_key}"]},
        {"tool": "veh_read_memory", "args": {"address": f"$0.registers.{ip_key}", "size": 2},
         "result_fields": ["address", "hex"]},
    ]})
    first, second = [entry["result"] for entry in report["results"]]
    assert first == {"registers": {ip_key: registers[ip_key]}}
    assert set(second) == {"address", "hex"} and len(second["hex"].split()) == 2


def test_output_budget_spills_complete_report(session, tmp_path):
    client, _ = session
    base = client.tool("veh_modules")["modules"][0]["baseAddress"]
    invalid = client.tool("veh_batch", {
        "steps": [{"tool": "veh_modules", "args": {}}],
        "max_output_bytes": 1024,
        "artifact_directory": "",
    })
    assert "must not be empty" in invalid["error"]
    report = client.tool("veh_batch", {
        "steps": [{"tool": "veh_read_memory", "args": {"address": base, "size": 4096}}],
        "max_output_bytes": 1024,
        "artifact_directory": str(tmp_path),
    })
    assert report["partial"] is True and report["partial_reason"] == "max_output_bytes"
    assert len(json.dumps(report, separators=(",", ":")).encode("utf-8")) <= 1024
    artifact = report["artifact"]
    path = tmp_path / os.path.basename(artifact["path"])
    assert path.exists() and os.path.samefile(path, artifact["path"])
    payload = path.read_bytes()
    assert hashlib.sha256(payload).hexdigest() == artifact["sha256"]
    full = json.loads(payload)
    assert full["totalSteps"] == artifact["count"] == 1
    assert len(full["results"][0]["result"]["hex"].split()) == 4096


def test_previously_missing_tools_are_callable(session):
    client, tid = session
    exception_info, stack, chain = _steps(client, [
        {"tool": "veh_exception_info", "args": {}},
        {"tool": "veh_stack_trace", "args": {"threadId": tid}},
        {"tool": "veh_read_pointer_chain", "args": {"base": "$1.frames.0.address", "offsets": ["0"]}},
    ])
    assert "not available" not in str(exception_info.get("error", ""))
    assert stack["count"] == stack["totalFrames"] > 0
    assert "error" not in chain, chain


def test_direct_address_parser_in_batch(session):
    client, _ = session
    modules = client.tool("veh_modules")["modules"]
    base = int(modules[0]["baseAddress"], 16)
    direct, literal = _steps(client, [
        {"tool": "veh_read_memory", "args": {"address": hex(base), "size": 2}},
        {"tool": "veh_read_memory", "args": {"address": f"{hex(base)}+0x0", "size": 2}},
    ])
    assert direct["hex"] == literal["hex"] == "4d 5a"


@pytest.mark.parametrize("tool", [
    "veh_batch", "veh_targeted_capture", "veh_toolbox",
])
def test_lifecycle_and_reentrant_tools_are_blocked(session, tool):
    client, _ = session
    (result,) = _steps(client, [{"tool": tool, "args": {}}])
    assert "not available in batch steps" in result["error"]


@pytest.mark.parametrize("tool", ["veh_detach", "veh_terminate"])
def test_session_end_tools_are_rejected_before_batch_execution(session, tool):
    client, _ = session
    report = client.tool("veh_batch", {"steps": [{"tool": tool, "args": {}}]})
    assert "detach/terminate" in report["error"]


@pytest.mark.parametrize("tool", ["veh_attach", "veh_launch"])
def test_session_start_tools_do_not_replace_an_active_batch_session(session, tool):
    client, _ = session
    report = client.tool("veh_batch", {"steps": [{"tool": tool, "args": {}}]})
    assert "only when no session is attached" in report["error"]
