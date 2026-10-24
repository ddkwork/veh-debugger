"""Localhost TLS/resident regression using host-only synthetic protocol peers."""
import ctypes
from ctypes import wintypes
import hashlib
import hmac
import json
import os
from pathlib import Path
import queue
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from unittest.mock import patch

from build_paths import RELEASE
from mcp_test_client import McpClient

BIN = Path(RELEASE)
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
MAGIC = 0x52484556
DOMAIN = b"VEH-REMOTE-CLIENT-v1"
KERNEL = ctypes.WinDLL("kernel32", use_last_error=True)
KERNEL.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
KERNEL.OpenProcess.restype = wintypes.HANDLE
KERNEL.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
KERNEL.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
KERNEL.CloseHandle.argtypes = (wintypes.HANDLE,)


def powershell(script, directory):
    environment = dict(os.environ, VEH_TEST_TEMP=str(directory))
    completed = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        env=environment, capture_output=True, timeout=30,
        creationflags=CREATE_NO_WINDOW)
    if completed.returncode:
        raise RuntimeError("certificate/private fixture operation failed")
    return completed.stdout.decode("utf-8-sig").strip()


def exact(connection, size, seconds=10):
    deadline = time.monotonic() + seconds
    result = bytearray()
    while len(result) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("TLS read deadline")
        connection.settimeout(remaining)
        part = connection.recv(size - len(result))
        if not part:
            raise EOFError("TLS connection closed")
        result.extend(part)
    return bytes(result)


def control(connection, kind, payload=b""):
    assert len(payload) <= 65536
    connection.sendall(struct.pack("<IIII", MAGIC, 1, kind, len(payload)) + payload)


def read_control(connection, kind):
    magic, version, actual, size = struct.unpack("<IIII", exact(connection, 16))
    assert (magic, version, actual) == (MAGIC, 1, kind), "invalid control header"
    assert size <= 65536, "oversized control payload"
    return exact(connection, size)


def connect(port, pin):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        peer = context.wrap_socket(raw, server_hostname="localhost")
    except BaseException:
        raw.close()
        raise
    assert hashlib.sha256(peer.getpeercert(binary_form=True)).hexdigest() == pin, "certificate pin"
    return peer


def authenticate(peer, token, proof=None):
    nonce = read_control(peer, 1)
    assert len(nonce) == 32, "nonce width"
    generated = hmac.digest(token, DOMAIN + nonce, "sha256")
    control(peer, 2, generated if proof is None else proof)
    assert read_control(peer, 3) == b"", "auth completion"
    return generated


def raw_open(port, pin, token, request):
    peer = connect(port, pin)
    try:
        authenticate(peer, token)
        control(peer, 4, json.dumps(request, separators=(",", ":")).encode())
        result = json.loads(read_control(peer, 5))
        assert result.get("success"), "resident work open"
        command, size = struct.unpack("<II", exact(peer, 8))
        assert (command, size) == (0x1000, 0), "ready event"
        return peer, result
    except BaseException:
        peer.close()
        raise


def raw_threads(peer):
    peer.sendall(struct.pack("<II", 0x20, 0))
    for _ in range(16):
        command, size = struct.unpack("<II", exact(peer, 8))
        assert size <= 65536, "fixture IPC size"
        payload = exact(peer, size)
        if command == 0x20:
            status, count = struct.unpack_from("<II", payload)
            assert (status, count) == (0, 1), "raw thread metadata"
            assert struct.unpack_from("<I", payload, 8)[0] == 77, "raw thread identity"
            return
    raise AssertionError("thread reply missing")


def wait_file(path, seconds=5):
    deadline = time.monotonic() + seconds
    while not path.exists():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("launched process completion")
        # Event/deadline wait yields immediately when the condition becomes visible.
        threading.Event().wait(min(0.02, remaining))


def run():
    runner = None
    clients = []
    target_handles = []
    certificate = None
    runner_lines = queue.Queue()
    checks = 0

    def passed(label):
        nonlocal checks
        checks += 1
        print("PASS " + label, flush=True)

    with tempfile.TemporaryDirectory(prefix="veh-tls-check-") as temporary:
        directory = Path(temporary)
        try:
            for name in ("veh-remote-runner.exe", "veh-mcp-server.exe", "guest_backend_fixture.exe"):
                assert (BIN / name).is_file(), "required executable missing"
            token = secrets.token_bytes(32)
            token_path = directory / "token.txt"
            token_path.write_bytes(token.hex().encode() + b"\r\n")
            fixture = powershell("""
$ErrorActionPreference='Stop'
$p=Join-Path $env:VEH_TEST_TEMP 'token.txt'
$acl=New-Object System.Security.AccessControl.FileSecurity
$acl.SetAccessRuleProtection($true,$false)
$user=[System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl.SetOwner($user)
foreach($sid in @($user.Value,'S-1-5-18','S-1-5-32-544')){
 $identity=New-Object System.Security.Principal.SecurityIdentifier($sid)
 $rule=New-Object System.Security.AccessControl.FileSystemAccessRule($identity,'FullControl','Allow')
 $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $p -AclObject $acl
$cert=New-SelfSignedCertificate -DnsName localhost -Type SSLServerAuthentication -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(1) -FriendlyName ('VEH localhost test '+[guid]::NewGuid())
$hash=[System.Security.Cryptography.SHA256]::Create()
try{$pin=([BitConverter]::ToString($hash.ComputeHash($cert.RawData))).Replace('-','').ToLowerInvariant()}finally{$hash.Dispose()}
@{thumbprint=$cert.Thumbprint;pin=$pin}|ConvertTo-Json -Compress
""", directory)
            metadata = json.loads(fixture)
            certificate = metadata["thumbprint"]
            pin = metadata["pin"]
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            backend = str(BIN / "guest_backend_fixture.exe")
            profile = {
                "listen": {"address": "127.0.0.1", "port": port},
                "certificate_sha256": pin, "token_file": str(token_path),
                "backends": {
                    "guest": {"path": backend, "target_scope": "guest"},
                    "machine": {"path": backend, "target_scope": "vm", "args": ["--metadata", "machine"]},
                    "host": {"path": backend, "target_scope": "host", "args": ["--metadata", "host-cap"], "allow_launch": True},
                }}
            runner_profile = directory / "runner.json"
            runner_profile.write_text(json.dumps(profile), encoding="utf-8")
            runner = subprocess.Popen(
                [str(BIN / "veh-remote-runner.exe"), "--profile", str(runner_profile)],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                creationflags=CREATE_NO_WINDOW)
            def read_runner():
                for line in runner.stderr:
                    runner_lines.put(line)
                runner_lines.put(None)
            runner_reader = threading.Thread(target=read_runner, daemon=True)
            runner_reader.start()
            ready = runner_lines.get(timeout=15)
            assert ready and b"listening" in ready, "resident runner startup"

            guest_request = {"backend": "guest", "operation": "attach", "target_scope": "guest", "pid": 424242}
            peer, first = raw_open(port, pin, token, guest_request)
            try:
                raw_threads(peer)
                original_work = first["work_id"]
                assert len(original_work) == 64 and first["outcome_unknown"] is False
            finally:
                peer.close()  # unexpected transport loss; retain backend lease
            # Unbind races socket close; retry only explicit busy replies, never mutating work.
            deadline = time.monotonic() + 5
            second = None
            for reconnect_attempt in range(3):
                if time.monotonic() >= deadline:
                    break
                peer = connect(port, pin)
                try:
                    authenticate(peer, token)
                    control(peer, 4, json.dumps(guest_request).encode())
                    reply = json.loads(read_control(peer, 5))
                    if not reply.get("success"):
                        assert reply.get("code") == "busy", "unexpected reconnect refusal"
                        threading.Event().wait(min(0.05, max(0, deadline - time.monotonic())))
                        continue
                    assert struct.unpack("<II", exact(peer, 8)) == (0x1000, 0)
                    raw_threads(peer)
                    second = reply
                    peer.sendall(struct.pack("<II", 0xF0, 0))
                    break
                finally:
                    peer.close()
            assert second and second["work_id"] == original_work, "retained work identity"
            assert second["outcome_unknown"] is False, "idle reconnect outcome"
            passed("TLS challenge, raw IPC threads and retained reconnect identity")

            peer = connect(port, pin)
            try:
                saved_proof = authenticate(peer, token)
            finally:
                peer.close()
            replay_rejected = False
            peer = connect(port, pin)
            try:
                try:
                    authenticate(peer, token, proof=saved_proof)
                except (EOFError, ssl.SSLError, ConnectionError):
                    replay_rejected = True
            finally:
                peer.close()
            assert replay_rejected, "replayed proof accepted"
            passed("fresh server nonce rejects prior connection proof")

            bad_token = directory / "bad-token.txt"
            bad_token.write_text(secrets.token_hex(32), encoding="ascii")
            # Same restrictive ACL as the valid token, so rejection tests auth itself.
            powershell("$ErrorActionPreference='Stop'; $d=$env:VEH_TEST_TEMP; Set-Acl -LiteralPath (Join-Path $d 'bad-token.txt') -AclObject (Get-Acl -LiteralPath (Join-Path $d 'token.txt'))", directory)
            mappings = {}
            for alias, scope in (("guest", "guest"), ("machine", "vm"), ("host", "host")):
                mappings[alias] = {"target_scope": scope, "remote": {
                    "address": "127.0.0.1", "port": port, "certificate_sha256": pin,
                    "token_file": str(token_path), "backend": alias, "timeout_ms": 20000}}
            mappings["badpin"] = json.loads(json.dumps(mappings["guest"]))
            mappings["badpin"]["remote"]["certificate_sha256"] = "0" * 64
            mappings["badauth"] = json.loads(json.dumps(mappings["guest"]))
            mappings["badauth"]["remote"]["token_file"] = str(bad_token)
            table = directory / "backends.json"
            table.write_text(json.dumps(mappings), encoding="utf-8")
            popen = subprocess.Popen
            def hidden_popen(*args, **kwargs):
                kwargs["creationflags"] = kwargs.get("creationflags", 0) | CREATE_NO_WINDOW
                return popen(*args, **kwargs)
            with patch("mcp_test_client.subprocess.Popen", hidden_popen):
                client = McpClient(env=dict(os.environ, VEH_BACKENDS=str(table)))
            clients.append(client)
            client.initialize()
            for alias in ("badpin", "badauth"):
                rejected = client.tool("veh_attach", {"backend": alias, "pid": 424243}, timeout=25)
                assert "error" in rejected, "invalid credentials accepted"
                assert "error" in client.tool("veh_threads"), "failed auth retained session"
            passed("frontend rejects wrong certificate pin and wrong PSK")
            attached = client.tool("veh_attach", {"backend": "guest", "pid": 424244}, timeout=25)
            assert attached.get("success") and attached["addressBits"] == 32, "guest attach"
            assert attached["backend"]["targetScope"] == "guest", "guest scope"
            assert client.tool("veh_threads")["threads"][0]["id"] == 77, "guest threads"
            for tool_name, arguments, fragment in (
                ("veh_set_breakpoint", {"address": "0x1000", "condition": "RAX == 1"}, "Conditional breakpoint"),
                ("veh_trace_basic_blocks", {"threadId": 77, "code_output": "file"}, "Target-side file"),
                ("veh_trace_basic_blocks", {"threadId": 77, "events_output": "file"}, "Target-side file"),
            ):
                direct = client.tool(tool_name, arguments)
                through_toolbox = client.tool("veh_toolbox", {
                    "operation": "call", "tool": tool_name, "arguments": arguments})
                batch = client.tool("veh_batch", {"steps": [{"tool": tool_name, "args": arguments}]})
                errors = [direct.get("error"), through_toolbox.get("error"),
                          batch["results"][0]["result"].get("error")]
                assert errors[0] and len(set(errors)) == 1 and fragment in errors[0], "remote rejection parity"
                assert batch["failed"] == 1 and batch["succeeded"] == 0, "batch rejection status"
            passed("conditional breakpoint/file trace rejection agrees in direct/toolbox/batch")
            rejected = client.tool("veh_launch", {"backend": "guest", "program": "synthetic.exe"})
            assert "error" in rejected, "guest process launch accepted"
            assert client.tool("veh_threads")["count"] == 1, "launch rejection lost prior guest session"
            assert client.tool("veh_detach").get("success"), "guest detach"
            passed("MCP guest metadata/threads and unsupported launch preserves session")

            machine = client.tool("veh_attach", {"backend": "machine", "target_scope": "vm"}, timeout=25)
            assert machine.get("success") and machine["backend"]["targetScope"] == "vm", "VM attach"
            assert client.tool("veh_detach").get("success"), "VM detach"
            passed("MCP VM scope attach")

            backend_workspace = os.environ.get("VEH_BACKEND_WORKSPACE")
            if backend_workspace:
                workspace = Path(backend_workspace).resolve(strict=True)
                with tempfile.TemporaryDirectory(prefix="tcp-localhost-", dir=workspace / "local") as backend_temp:
                    local = Path(backend_temp)
                    local_table = local / "backends.json"
                    local_table.write_text(json.dumps(mappings), encoding="utf-8")
                    local_profile = local / "profile.json"
                    local_profile.write_text(json.dumps({
                        "mcp_executable": str(BIN / "veh-mcp-server.exe"),
                        "backend_config": str(local_table),
                        "open_arguments": {"backend": "guest", "pid": 424246},
                        "open_expect": {"backend.targetScope": "guest", "addressBits": 32},
                        "checks": [
                            {"tool": "veh_launch", "arguments": {"backend": "guest", "program": "synthetic.exe"}, "expect_error": True},
                            {"tool": "veh_threads", "expect": {"count": 1, "threads.0.id": 77}}],
                        "reconnect_arguments": {"backend": "guest", "pid": 424246},
                        "deadline_seconds": 60}), encoding="utf-8")
                    regression = subprocess.run(
                        [sys.executable, "-B", str(workspace / "tools" / "mcp_remote.py"),
                         "--tcp-profile", str(local_profile)], cwd=workspace,
                        capture_output=True, timeout=90, creationflags=CREATE_NO_WINDOW)
                    assert regression.returncode == 0, "backend protected-profile TCP regression"
                passed("backend mcp_remote protected-profile TCP regression")

            marker = directory / "launched.txt"
            code = "from pathlib import Path;Path(" + repr(str(marker)) + ").write_text('done')"
            launched = client.tool("veh_launch", {
                "backend": "host", "program": sys.executable, "args": ["-c", code], "stopOnEntry": True}, timeout=25)
            assert launched.get("success"), "host launch"
            target = KERNEL.OpenProcess(0x00100000 | 0x0001, False, launched["pid"])
            assert target, "owned launched process handle"
            target_handles.append(target)
            assert not marker.exists(), "stopOnEntry allowed entry execution"
            assert client.tool("veh_detach").get("success"), "host detach"
            wait_file(marker)
            assert KERNEL.WaitForSingleObject(target, 5000) == 0, "detached owned target did not exit"
            passed("host stop-entry launch detach resumes owned primary thread")
        finally:
            cleanup_failures = []
            for client in clients:
                try:
                    client.close(terminate_target=False)
                    assert client.proc.poll() is not None, "owned MCP process remains"
                except Exception:
                    cleanup_failures.append("MCP cleanup")
            for handle in target_handles:
                try:
                    if KERNEL.WaitForSingleObject(handle, 0) == 258:
                        assert KERNEL.TerminateProcess(handle, 1), "owned target cleanup failed"
                        assert KERNEL.WaitForSingleObject(handle, 5000) == 0, "owned target remains"
                except Exception:
                    cleanup_failures.append("target cleanup")
                finally:
                    KERNEL.CloseHandle(handle)
            if runner is not None:
                try:
                    if runner.poll() is None:
                        runner.terminate()
                        try:
                            runner.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            runner.kill()
                            runner.wait(timeout=5)
                    runner_reader.join(timeout=2)
                    runner.stderr.close()
                    assert runner.poll() is not None, "owned resident remains"
                except Exception:
                    cleanup_failures.append("resident cleanup")
            if certificate is not None:
                # Provider removes this test certificate and its private key only.
                cleanup = "$ErrorActionPreference='Stop'; Remove-Item -LiteralPath ('Cert:\\CurrentUser\\My\\' + '" + certificate + "') -DeleteKey"
                try:
                    powershell(cleanup, directory)
                except Exception:
                    cleanup_failures.append("certificate/private key cleanup")
            if cleanup_failures:
                raise RuntimeError(", ".join(cleanup_failures))
    print(f"PASS {checks} localhost remote transport checks; owned processes/certificate/token cleaned")


if __name__ == "__main__":
    run()
