#!/usr/bin/env python3
"""One-shot or persistent static analysis, and isolated persistent LLDB JSON RPC."""
import json
import sys
import traceback
import analysis
from session import AnalysisSession

session = AnalysisSession()

def analyzed(q):
    a = session.analyze(q['path'], int(q.get('slice', 0)), q.get('functionNames'), q.get('refresh', False))
    if q.get('sha256') and q['sha256'] != a['sha256']:
        raise ValueError('Binary changed since analysis; reopen it before continuing')
    return a

def static(q):
    action=q.get('action','analyze')
    if action=='analyze': return analyzed(q)
    if action=='decompile':
        import decompiler
        return decompiler.decompile(analyzed(q),q.get('function',''),q.get('names'),q.get('abi','auto'))
    if action=='signatureLearn':
        import recognition
        a=analyzed(q)
        if q.get('sha256') and q['sha256']!=a['sha256']: raise ValueError('Binary changed; reopen it before learning signatures')
        return recognition.learn(a,q['library'],q.get('functions'))
    if action=='signatureInstall':
        import recognition
        return recognition.install(q['path'])
    if action=='patchPreview':
        import patching
        return patching.preview(q['path'],q['address'],q['kind'],q.get('value',''),int(q.get('slice',0)),q.get('sha256',''),q.get('section',''),analyzed=analyzed(q))
    if action=='hex': return analysis.hex_view(q['path'],q.get('offset',0),q.get('count',512))
    if action=='search': return analysis.search(q['path'],q['query'],q.get('mode','text'))
    if action=='compare': return analysis.compare(q['path'],q['other'])
    if action=='patch': return analysis.patch(q['path'],q['output'],int(q['offset']),q['bytes'],q.get('sha256',''))
    raise ValueError('Unknown analysis action')

def main():
    debug='--debug' in sys.argv
    persistent='--static-session' in sys.argv
    debugger=None
    try:
        for line in sys.stdin:
            q={}
            try:
                if len(line)>1024*1024: raise ValueError('Request too large')
                q=json.loads(line)
                if debug:
                    if debugger is None:
                        from debugger import Debugger
                        debugger=Debugger()
                    result=debugger.handle(q)
                elif q.get('action')=='shutdown': result={}
                else: result=static(q)
                response=dict(id=q.get('id',0),ok=True,result=result)
            except Exception as e:
                response=dict(id=q.get('id',0),ok=False,error=str(e))
            print(json.dumps(response,ensure_ascii=True),flush=True)
            if (not debug and not persistent) or q.get('action')=='shutdown': break
    finally:
        if debugger and q.get('action')!='shutdown':
            try: debugger.handle({'action':'shutdown'})
            except Exception: pass
if __name__=='__main__': main()
