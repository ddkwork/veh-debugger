"""Explicit VM namespace against a host fixture, with no target process."""
import json
import os
from pathlib import Path
import tempfile
from build_paths import RELEASE
from mcp_test_client import McpClient
FIXTURE=Path(RELEASE)/'guest_backend_fixture.exe'

def run():
    client=McpClient()
    try:
        client.initialize()
        guest={'pid':2147418112,'agent':str(FIXTURE),'target_scope':'guest'}
        assert client.tool('veh_attach',guest).get('success')
        vm={'agent':str(FIXTURE),'target_scope':'vm','agent_args':['--metadata','machine']}
        assert 'error' in client.tool('veh_attach',{**vm,'pid':1})
        assert client.tool('veh_threads')['count']==1,'invalid VM request replaced prior session'
        attached=client.tool('veh_attach',vm)
        assert attached.get('success') and attached['backend']['targetScope']=='vm' and 'pid' not in attached and 'addressBits' not in attached,attached
        assert not attached['backend']['stopsThreads'],attached
        assert 'error' in client.tool('veh_system_memory',{'operation':'search','space':'physical','address':'0x0','size':16,'pattern':'90'})
        assert client.tool('veh_virtual_machine',{'operation':'status'})['state']=='paused'
        traced=client.tool('veh_virtual_machine',{'operation':'trace','max_instructions':137})
        assert traced.get('success') and traced['completed']==137 and traced['lost']==73,traced
        rejected=client.tool('veh_launch',{'program':'host-not-created.exe',**vm})
        assert 'error' in rejected
        assert client.tool('veh_virtual_machine',{'operation':'status'})['state']=='paused'
        for mode in ('machine-wrong-pid','machine-bad-width','machine-wrong-scope','machine-guest-cap','machine-truncated'):
            failed=client.tool('veh_attach',{**vm,'agent_args':['--metadata',mode]})
            assert 'error' in failed,(mode,failed)
            assert 'error' in client.tool('veh_virtual_machine',{'operation':'status'}),mode
        assert 'error' in client.tool('veh_attach',{'target_scope':'vm'})
        with tempfile.TemporaryDirectory(prefix='veh-vm-backend-') as temp:
            table=Path(temp)/'backends.json'
            table.write_text(json.dumps({'machine':{'path':str(FIXTURE),'args':['--metadata','machine'],'target_scope':'vm'}}),encoding='utf-8')
            with McpClient(env=dict(os.environ,VEH_BACKENDS=str(table))) as registered:
                registered.initialize()
                assert registered.tool('veh_attach',{'backend':'machine'}).get('success')
                assert registered.tool('veh_detach').get('success')
        print('PASS VM no-PID agent routing, metadata rejection, prior-session preservation, VM control/trace and registered scope')
    finally:client.close(terminate_target=False)

if __name__=='__main__':run()
