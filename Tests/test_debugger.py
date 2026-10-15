"""Real local LLDB integration; run from a normal Mac terminal with debugger access."""
import json
from pathlib import Path
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'Engine'))
from debugger import Debugger

def main():
    root=Path(__file__).resolve().parents[1]
    d=Debugger(); checks=[]
    def check(name,condition):
        if not condition: raise AssertionError(name)
        checks.append(name); print('PASS',name,flush=True)
    def wait_for(expected,timeout=12):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            s=d.handle({'action':'snapshot'})
            if s['state'] in expected: return s
            time.sleep(.05)
        raise AssertionError('Timed out waiting for '+str(expected)+'; got '+s['state'])
    try:
        s=d.handle({'action':'target','path':str(root/'Examples/asteria-sample')})
        check('target ready',s['state']=='ready')
        s=d.handle({'action':'breakpoint','spec':'score_input'})
        check('symbol breakpoint resolved',s['breakpoints'][0]['locations']>0)
        d.handle({'action':'launch','stopAtEntry':True})
        s=wait_for({'stopped'})
        check('local launch and entry stop',len(s['frames'])>0)
        d.handle({'action':'continue'})
        s=wait_for({'stopped','exited'})
        check('breakpoint hit',s['state']=='stopped' and s['breakpoints'][0]['hits']==1)
        check('thread and frame snapshot',bool(s['threads']) and any('score_input' in f['name'] for f in s['frames']))
        check('register snapshot',any(r['name']=='pc' or r['name']=='rip' for r in s['registers']))
        check('local variables',any(v['name']=='text' for v in s['variables']))
        s=d.handle({'action':'frame','id':1})
        check('caller frame selection',any(v['name']=='argc' for v in s['variables']))
        s=d.handle({'action':'expression','expression':'argc'})
        check('caller expression context','1' in s['result'])
        s=d.handle({'action':'frame','id':0})
        s=d.handle({'action':'memory','address':s['pc'],'count':32})
        check('runtime memory read',bool(s['result']))
        pc=s['pc']; d.handle({'action':'instructionInto'}); s=wait_for({'stopped'})
        check('instruction stepping changes PC',s['pc']!=pc)
        s=d.handle({'action':'expression','expression':'atlas_counter'})
        check('expression evaluation','7' in s['result'])
        d.handle({'action':'continue'}); s=wait_for({'exited'})
        check('continue through exit',s['state']=='exited' and 'status 0' in s['description'])
        print(json.dumps({'passed':checks,'count':len(checks)},indent=2))
    finally: d.handle({'action':'shutdown'})
if __name__=='__main__': main()
