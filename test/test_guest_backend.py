"""Guest PID namespace integration; fixture runs on the host, not in a guest."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from build_paths import RELEASE
from mcp_test_client import McpClient

FIXTURE = Path(RELEASE) / 'guest_backend_fixture.exe'


def run():
    # A real host PID deliberately collides with the synthetic guest PID.
    host = subprocess.Popen([sys.executable, '-c', 'import sys; sys.stdin.read()'], stdin=subprocess.PIPE)
    client = McpClient()
    try:
        client.initialize()
        args = {'pid': host.pid, 'agent': str(FIXTURE), 'target_scope': 'guest'}
        attached = client.tool('veh_attach', args)
        assert attached.get('success'), attached
        assert attached['backend']['targetScope'] == 'guest', attached
        assert attached['addressBits'] == 32, attached
        threads = client.tool('veh_threads')
        assert threads['count'] == 1 and threads['threads'][0]['id'] == 77, threads
        assembly = client.tool('veh_disassemble', {'address': '0x1000', 'count': 2})
        assert 'edx' in json.dumps(assembly).lower() and 'inc' in json.dumps(assembly).lower(), assembly
        assert 'error' in client.tool('veh_pause'), 'Unsupported pause reported success'
        assert 'error' in client.tool('veh_terminate'), 'Unsupported terminate reported success'
        assert client.tool('veh_threads')['count'] == 1, 'Unsupported terminate detached guest'
        # A refused step must return now, not wait five seconds for an event.
        for step in ('veh_step_in', 'veh_step_over', 'veh_step_out'):
            started = time.monotonic()
            refused = client.tool(step, {'threadId': 77}, timeout=2)
            assert 'without a stop' in refused.get('error', ''), (step, refused)
            assert time.monotonic() - started < 2, (step, 'refusal was not immediate')
        # The host process can exit without ending the guest debugging session.
        host.stdin.close()
        host.wait(timeout=5)
        assert client.tool('veh_threads')['count'] == 1
        assert client.tool('veh_detach').get('success')
        # Hypervisor tracing stays non-stopping even when Continue/Pause exist.
        traced = client.tool('veh_attach', {**args, 'agent_args': ['--metadata', 'trace']})
        assert traced.get('success'), traced
        empty = client.tool('veh_trace_callers', {'address': '0x1000', 'duration_ms': 50})
        assert empty.get('totalHits') == 0 and empty.get('callers') == [], empty
        refused = client.tool('veh_trace_callers', {'address': '0x2000', 'duration_ms': 50})
        assert 'error' in refused and 'unsupported' in refused['error'], refused
        assert client.tool('veh_threads')['threads'][0]['name'] == 'untouched', 'Trace sent Continue/Pause'
        assert client.tool('veh_detach').get('success')
        # A failed query must not masquerade as an empty successful list.
        for mode, expected in (('reply-errors', 'unsupported'), ('reply-truncated', 'incomplete'),
                               ('reply-empty', None)):
            result = client.tool('veh_attach', {**args, 'agent_args': ['--metadata', mode]})
            assert result.get('success'), result
            for tool in ('veh_threads', 'veh_modules'):
                result = client.tool(tool)
                if expected:
                    assert expected in result.get('error', ''), (mode, tool, result)
                    assert 'count' not in result, result
                else:
                    assert result.get('count') == 0 and 'error' not in result, result
            batch = client.tool('veh_batch', {'steps': [{'tool': 'veh_threads', 'args': {}}]})
            result = batch['results'][0]['result']
            if expected:
                assert expected in result.get('error', ''), batch
            else:
                assert result.get('count') == 0, batch
            if mode == 'reply-errors':
                for steps, expected_error in ((1, 'execution error'), (2, 'not found'),
                                             (3, 'rejected arguments'), (4, 'unsupported'),
                                             (5, 'resource limit'), (7, 'incomplete')):
                    result = client.tool('veh_trace_register', {'threadId': 77, 'register': 'eax',
                                                               'max_steps': steps})
                    assert expected_error in result.get('error', ''), (steps, result)
                result = client.tool('veh_trace_register', {'threadId': 77, 'register': 'eax', 'max_steps': 6})
                assert result.get('found') is False and 'error' not in result, result
                for tool, arguments in (
                    ('veh_trace_memory', {'address': '0x1000', 'size': 1, 'timeout_ms': 10}),
                    ('veh_trace_calls', {'addresses': ['0x1000'], 'duration_ms': 10})):
                    result = client.tool(tool, arguments)
                    assert 'unsupported' in result.get('error', '').lower(), result
            assert client.tool('veh_detach').get('success')
        for mode in ('wrong-pid', 'bad-width', 'wrong-scope', 'not-found', 'truncated', 'host-cap'):
            result = client.tool('veh_attach', {**args, 'agent_args': ['--metadata', mode]})
            assert 'error' in result, (mode, result)
            assert 'error' in client.tool('veh_threads'), (mode, 'invalid session remained attached')
        # An unconfigured guest peer also fails before a host target is opened.
        result = client.tool('veh_attach', {'pid': host.pid, 'agent': str(FIXTURE)})
        assert 'error' in result and 'scope' in result['error'].lower(), result
        for scope in ('guest', 'invalid'):
            assert 'error' in client.tool('veh_attach', {'pid': host.pid, 'target_scope': scope})
        launch = client.tool('veh_launch', {'program': sys.executable, 'agent': str(FIXTURE),
                                            'target_scope': 'guest', 'stopOnEntry': False})
        assert 'error' in launch and 'guest process launch' in launch['error'].lower(), launch
        # Backend selection supplies guest scope without repeating it per call.
        with tempfile.TemporaryDirectory(prefix='veh-guest-backend-') as temp:
            table = Path(temp) / 'backends.json'
            table.write_text(json.dumps({'synthetic': {'path': str(FIXTURE), 'target_scope': 'guest'}}), encoding='utf-8')
            env = dict(os.environ, VEH_BACKENDS=str(table))
            with McpClient(env=env) as configured:
                configured.initialize()
                result = configured.tool('veh_attach', {'pid': host.pid, 'backend': 'synthetic'})
                assert result.get('success') and result['backend']['targetScope'] == 'guest', result
                assert configured.tool('veh_detach').get('success')
        print('PASS guest metadata/cleanup, step refusals, zero-call trace and no hypervisor resume/pause')
    finally:
        try:
            if client.proc.poll() is None:
                client.tool('veh_detach', timeout=5)
        except Exception:
            pass
        client.close(terminate_target=False)
        if host.poll() is None:
            host.terminate()
            host.wait(timeout=5)


if __name__ == '__main__':
    run()
