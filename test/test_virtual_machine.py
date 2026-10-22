"""MCP VM-scope behavior against a synthetic host fixture; no guest execution."""
import json
from pathlib import Path
from build_paths import RELEASE
from mcp_test_client import McpClient

FIXTURE = Path(RELEASE) / 'guest_backend_fixture.exe'

def run():
    client=McpClient()
    try:
        client.initialize()
        attach={'pid':2147418112,'agent':str(FIXTURE),'target_scope':'guest'}
        assert client.tool('veh_attach',{**attach,'agent_args':['--metadata','vm']}).get('success')
        assert client.tool('veh_virtual_machine',{'operation':'status'})=={'success':True,'scope':'virtualMachine','state':'paused'}
        assert client.tool('veh_virtual_machine',{'operation':'resume'})['state']=='running'
        assert client.tool('veh_virtual_machine',{'operation':'pause'})['state']=='paused'
        request={'operation':'trace','max_instructions':137,'duration_ms':100,'cpu':0,'cpl_mask':1,'cr3_roots':['0x1000'],'rip_begin':'0x9000','rip_end':'0x9011'}
        trace=client.tool('veh_virtual_machine',request)
        assert trace.get('success') and (trace['completed'],trace['kept'],trace['lost'])==(137,64,73),trace
        assert trace['scope']=='virtualMachine' and trace['traceScope']=='vCPU' and trace['engine']=='interpreter'
        assert trace['records'][0]['timestampNs']=='9007199254740993',trace
        assert trace['records'][63]['sequence']==64 and trace['records'][0]['ip'].lower()=='0x900f'
        through_toolbox=client.tool('veh_toolbox',{'operation':'call','tool':'veh_virtual_machine','arguments':request})
        assert through_toolbox.get('result')==trace,'Toolbox result differs'
        for bad in ({'max_instructions':4097},{'duration_ms':0},{'cpu':-1},{'cpl_mask':0},{'cr3_roots':['0x1001']},{'rip_begin':'0x10000000000000000'}):
            assert 'error' in client.tool('veh_virtual_machine',{**request,**bad}),bad
        nested=client.tool('veh_batch',{'steps':[{'tool':'veh_virtual_machine','args':{'operation':'resume'}}]})
        assert 'not available in batch' in json.dumps(nested),nested
        assert client.tool('veh_virtual_machine',{'operation':'status'})['state']=='paused'
        for mode in ('vm-bad-trace','vm-truncated','vm-failure'):
            assert client.tool('veh_attach',{**attach,'agent_args':['--metadata',mode]}).get('success')
            failed=client.tool('veh_virtual_machine',request)
            assert 'error' in failed,failed
            if mode=='vm-failure':
                assert not failed['success'] and failed['completed']==2 and len(failed['records'])==2 and failed['executionStatus']==23,failed
            else:
                assert 'records' not in failed,failed
        assert client.tool('veh_detach').get('success')
        print('PASS explicit VM scope, fixed batch records/loss, exact timestamps, toolbox parity, malformed/partial responses and nested exclusion')
    finally:
        client.close(terminate_target=False)

if __name__=='__main__':run()
