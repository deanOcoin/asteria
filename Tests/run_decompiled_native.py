"""Isolated native differential runner: the parent applies a hard timeout."""
import ctypes
import json
import sys
q=json.load(sys.stdin)
original=ctypes.CDLL(q['original']); generated=ctypes.CDLL(q['generated'])
for case in q['cases']:
    name=case['name']; fn=getattr(generated,name); ref=getattr(original,name)
    fn.argtypes=ref.argtypes=[ctypes.c_uint64,ctypes.c_uint64]
    fn.restype=ctypes.c_uint64; ref.restype=ctypes.c_uint64 if name=='dc_wide' else ctypes.c_uint32
    for x,y in case['pairs']:
        # Flush progress so a timeout identifies the failing function/input.
        print(json.dumps({'current':[name,x,y]}),flush=True)
        actual=fn(x,y)&case['mask']; expected=ref(x,y)&case['mask']
        if actual!=expected:
            print(json.dumps({'failure':[name,x,y,actual,expected]}),flush=True); sys.exit(1)
print(json.dumps({'ok':True}),flush=True)
