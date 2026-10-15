"""Provenance-preserving scalar decompiler; LLVM only decodes bytes, the IR here is its own.
Addresses are static VAs, spans are offsets into the complete original file."""
from dataclasses import dataclass, field, replace
from collections import Counter, defaultdict
import copy
import hashlib
import json
import re

VERSION = '0.3.0'
MAX_FUNCTION = 3000
MAX_BLOCKS = 256


def number(s):
    s = s.strip().lstrip('#').strip()
    try: return int(s, 0)
    except ValueError:
        try: return int(s, 16) if s.endswith('h') else None
        except ValueError: return None


def ident(s):
    s = re.sub(r'[^A-Za-z0-9_]', '_', s.lstrip('_')) or 'unnamed'
    if s[0].isdigit(): s = 'fn_' + s
    if s in {'if','else','while','for','return','switch','case','break','continue','void','int','char','long','short','float','double','struct','union','default','goto','unsigned','signed','const','volatile','sizeof','static','auto','register','do','enum','typedef','extern'}: s = 'value_' + s
    return s[:100]


def operands(s):
    s = s.split(';')[0].split('//')[0]
    s = re.sub(r'\s*<[^>]*>', '', s).strip()
    result, start, depth = [], 0, 0
    for i, c in enumerate(s):
        if c in '[({': depth += 1
        if c in '])}': depth -= 1
        if c == ',' and depth == 0:
            result.append(s[start:i].strip()); start = i + 1
    if s[start:].strip(): result.append(s[start:].strip())
    return result


@dataclass(frozen=True)
class E:
    op: str
    args: tuple = ()
    bits: int = 64
    value: object = None
    origins: frozenset = frozenset()

    def at(self, *addresses):
        return replace(self, origins=self.origins | frozenset(addresses))

    def refs(self):
        if self.op == 'var': return {self.value}
        return set().union(*(a.refs() for a in self.args)) if self.args else set()

    def sources(self):
        return self.origins | (frozenset().union(*(a.sources() for a in self.args)) if self.args else frozenset())

    def substitute(self, name, value):
        if self.op == 'var' and self.value == name: return value.at(*self.origins)
        return simplify(replace(self, args=tuple(a.substitute(name, value) for a in self.args)))

    def effect(self):
        return self.op in ('load','unknown') or any(a.effect() for a in self.args)

    def text(self, names=None):
        names = names or {}
        t = lambda e: e.text(names)
        if self.op == 'var': return names.get(self.value, self.value)
        if self.op == 'function': return self.value
        if self.op == 'const':
            return str(self.value) if -10 <= self.value <= 99 else ('-0x%x' % -self.value if self.value < 0 else '0x%x' % self.value)
        if self.op == 'string': return json.dumps(self.value, ensure_ascii=True)
        if self.op == 'addr': return '&' + ident(str(self.value))
        if self.op in ('cast','signed'):
            return '(%sint%d_t)%s' % ('' if self.op == 'signed' else 'u', self.bits, t(self.args[0]))
        if self.op == 'load': return 'load_%s%d(%s)' % ('i' if self.value else 'u', self.bits, t(self.args[0]))
        if self.op == 'select': return '(%s ? %s : %s)' % tuple(t(a) for a in self.args)
        if self.op == 'not': return '!' + t(self.args[0])
        if self.op == 'neg': return '(-%s)' % t(self.args[0])
        if self.op == 'inv': return '(~%s)' % t(self.args[0])
        if self.op == 'unknown': return 'unknown_%s()' % ident(str(self.value))
        if self.op == 'intrinsic': return '%s(%s)' % (self.value, ', '.join(t(a) for a in self.args))
        if self.op in ('+','-','*','/','%','&','|','^','<<','>>','==','!=','<','<=','>','>=','&&','||'):
            rendered='(' + (' ' + self.op + ' ').join(t(a) for a in self.args) + ')'
            if self.op in ('+','-','*','&','|','^','<<','>>') and self.bits<32: return '(uint%d_t)%s'%(self.bits,rendered)
            return rendered
        return '%s(%s)' % (self.op, ', '.join(t(a) for a in self.args))


def C(n, bits=64): return E('const', bits=bits, value=n & ((1 << bits)-1) if n >= 0 else n)
def V(name, bits=64): return E('var', bits=bits, value=name)
def X(op, *args, bits=64, value=None): return simplify(E(op, tuple(args), bits, value))
def cast(e, bits, signed=False): return X('signed' if signed else 'cast', e, bits=bits)


def simplify(e):
    a = e.args
    source = e.sources()
    def keep(v): return v.at(*source)
    if e.op == 'cast' and a:
        if a[0].op == 'const': return keep(C(a[0].value & ((1 << e.bits)-1), e.bits))
        if a[0].bits == e.bits: return keep(a[0])
        if a[0].op == 'cast' and e.bits <= a[0].bits: return keep(cast(a[0].args[0], e.bits))
    if e.op == 'signed' and a and a[0].op == 'const':
        n = a[0].value & ((1 << e.bits)-1)
        return keep(C(n - (1 << e.bits) if n & (1 << (e.bits-1)) else n, e.bits))
    if len(a) == 2:
        l, r = a
        if l.op == r.op == 'const':
            x, y = l.value, r.value
            calc = {'+':lambda:x+y, '-':lambda:x-y, '*':lambda:x*y, '&':lambda:x&y, '|':lambda:x|y, '^':lambda:x^y,
                    '<<':lambda:x << (y % e.bits), '>>':lambda:x >> (y % e.bits), '==':lambda:int(x==y), '!=':lambda:int(x!=y),
                    '<':lambda:int(x<y), '<=':lambda:int(x<=y), '>':lambda:int(x>y), '>=':lambda:int(x>=y)}
            if e.op in calc: return keep(C(calc[e.op]() & ((1 << e.bits)-1), e.bits))
        if r.op == 'const' and r.value == 0 and e.op in ('+','-','|','^','<<','>>'): return keep(l)
        if r.op == 'const' and r.value == 1 and e.op == '*': return keep(l)
        if l == r and e.op in ('^','-'): return keep(C(0,e.bits))
        if l.op=='const' and l.value==0 and e.op in ('+','|','^'): return keep(r)
    if e.op == 'not' and a:
        rev = {'==':'!=','!=':'==','<':'>=','>=':'<','>':'<=','<=':'>'}
        if a[0].op in rev: return keep(replace(a[0],op=rev[a[0].op]))
        if a[0].op == 'not': return keep(a[0].args[0])
        if a[0].op in ('&&','||'): return keep(X('||' if a[0].op=='&&' else '&&',*(X('not',v,bits=1) for v in a[0].args),bits=1))
        if a[0].op == 'const': return keep(C(int(not a[0].value),1))
    if e.op == 'select' and a and a[0].op == 'const': return keep(a[1] if a[0].value else a[2])
    return e


@dataclass
class Op:
    kind: str
    dst: str = ''
    expr: E = None
    origins: set = field(default_factory=set)
    detail: str = ''
    target: int = None
    args: list = field(default_factory=list)
    def refs(self):
        return (self.expr.refs() if self.expr else set()) | set().union(*(a.refs() for a in self.args))
    def sources(self):
        return set(self.origins) | (set(self.expr.sources()) if self.expr else set()) | set().union(*(set(a.sources()) for a in self.args))
    def barrier(self): return self.kind in ('store','call','opaque','stack')
    def substitute(self, name, expr):
        if self.expr: self.expr = self.expr.substitute(name,expr)
        self.args = [a.substitute(name,expr) for a in self.args]


@dataclass
class Block:
    start: int
    ins: list
    succ: list = field(default_factory=list)
    pred: set = field(default_factory=set)
    ops: list = field(default_factory=list)
    env: dict = field(default_factory=dict)
    inputs: set = field(default_factory=set)
    outputs: set = field(default_factory=set)
    livein: set = field(default_factory=set)
    liveout: set = field(default_factory=set)
    omitted: set = field(default_factory=set)
    term: Op = None


def cfg(instructions):
    addresses = {int(i['address'],16) for i in instructions}
    leaders = {int(instructions[0]['address'],16)}
    for n, i in enumerate(instructions):
        target = number(i.get('target',''))
        if i['kind'] in ('branch','jump') and target in addresses: leaders.add(target)
        if i['kind'] in ('branch','jump','return') or i['mnemonic'] in ('ud2','brk','hlt','int3'):
            if n+1<len(instructions): leaders.add(int(instructions[n+1]['address'],16))
    blocks, current = [], None
    for i in instructions:
        addr = int(i['address'],16)
        if addr in leaders:
            current = Block(addr,[]); blocks.append(current)
        current.ins.append(i)
    if len(blocks)>MAX_BLOCKS: raise ValueError('Function exceeds the 256-block decompiler limit')
    by = {b.start:b for b in blocks}
    for n,b in enumerate(blocks):
        i=b.ins[-1]; target=number(i.get('target','')); fall=blocks[n+1].start if n+1<len(blocks) else None
        if i['kind'] in ('branch','jump'):
            if target in by: b.succ.append(target)
            if i['kind']=='branch' and fall is not None: b.succ.append(fall)
        elif i['kind']!='return' and i['mnemonic'] not in ('ud2','brk','hlt','int3') and fall is not None: b.succ.append(fall)
        b.succ=list(dict.fromkeys(b.succ))
        for s in b.succ: by[s].pred.add(b.start)
    return blocks


X86 = {
    'rax':('rax',64,0),'eax':('rax',32,0),'ax':('rax',16,0),'al':('rax',8,0),'ah':('rax',8,8),
    'rbx':('rbx',64,0),'ebx':('rbx',32,0),'bx':('rbx',16,0),'bl':('rbx',8,0),'bh':('rbx',8,8),
    'rcx':('rcx',64,0),'ecx':('rcx',32,0),'cx':('rcx',16,0),'cl':('rcx',8,0),'ch':('rcx',8,8),
    'rdx':('rdx',64,0),'edx':('rdx',32,0),'dx':('rdx',16,0),'dl':('rdx',8,0),'dh':('rdx',8,8),
}
for full, d, w, byte in [('rsi','esi','si','sil'),('rdi','edi','di','dil'),('rsp','esp','sp','spl'),('rbp','ebp','bp','bpl')]:
    for n,bits in [(full,64),(d,32),(w,16),(byte,8)]: X86[n]=(full,bits,0)
for n in range(8,16):
    for suf,bits in [('',64),('d',32),('w',16),('b',8)]: X86['r%d%s'%(n,suf)]=('r%d'%n,bits,0)


def reg(s, arm):
    s=s.strip().lower()
    if arm:
        if s in ('sp','wsp'): return ('sp',64 if s=='sp' else 32,0)
        if s in ('xzr','wzr'): return ('zero',64 if s=='xzr' else 32,0)
        if s=='fp': return ('x29',64,0)
        if s=='lr': return ('x30',64,0)
        if re.fullmatch('[xw]([0-9]|[12][0-9]|30)',s): return ('x'+s[1:],64 if s[0]=='x' else 32,0)
    else: return X86.get(s)
    return None


class Lifter:
    def __init__(self, a, blocks, abi='auto', recover_stack=True):
        self.a=a; self.blocks=blocks; self.arm=a['arch'] in ('arm64','arm64e','aarch64'); self.bits=a['bits'] or 64
        self.windows=a['format'] in ('PE','COFF')
        self.abi=abi if abi!='auto' else ('aapcs64' if self.arm else ('cdecl32' if self.bits==32 else ('win64' if self.windows else 'sysv64')))
        allowed = ['aapcs64'] if self.arm else (['cdecl32'] if self.bits==32 else ['sysv64','win64'])
        if self.abi not in allowed: raise ValueError('ABI is incompatible with this architecture')
        self.argregs=['x%d'%i for i in range(8)] if self.arm else (['rcx','rdx','r8','r9'] if self.abi=='win64' else ([] if self.bits==32 else ['rdi','rsi','rdx','rcx','r8','r9']))
        self.ret='x0' if self.arm else 'rax'; self.sp='sp' if self.arm else 'rsp'; self.fp='x29' if self.arm else 'rbp'
        self.caller=(['x%d'%i for i in range(19)] if self.arm else (['rax','rcx','rdx','r8','r9','r10','r11'] if self.abi=='win64' else ['rax','rcx','rdx','rsi','rdi','r8','r9','r10','r11']))
        self.widths={}; self.slots={}; self.diagnostics=[]; self.unsupported=set(); self.counter=0
        self.frame_states=self.find_frames() if recover_stack else {}; self.stack_inputs={}; self.bookkeeping=set(); self.stack_escaped=False

    def warning(self,message):
        if message not in self.diagnostics: self.diagnostics.append(message)

    def find_frames(self):
        # A must analysis: disagreement forgets an affine stack address.
        before={self.blocks[0].start:{self.sp:0}}; outgoing={}; by={b.start:b for b in self.blocks}
        for _ in range(len(self.blocks)*3+1):
            change=False
            for b in self.blocks:
                if b.start!=self.blocks[0].start:
                    known=[outgoing[p] for p in b.pred if p in outgoing]
                    if not known: continue
                    state={k:v for k,v in known[0].items() if all(s.get(k)==v for s in known[1:])}
                else: state={self.sp:0}
                before[b.start]=dict(state)
                for i in b.ins: self.frame_step(state,i)
                if outgoing.get(b.start)!=state: outgoing[b.start]=dict(state); change=True
            if not change: break
        return before

    def frame_step(self,state,i):
        p=operands(i['operands']); m=i['mnemonic'].lower()
        if m in ('bl','blr','blraa','blrab','call','callq'):
            for key in self.caller: state.pop(key,None)
            return
        if not p: return
        r=reg(p[0],self.arm); key=r[0] if r else ''
        if self.arm:
            if m in ('add','sub') and len(p)>=3 and r:
                src=reg(p[1],True); n=number(p[2])
                if src and src[0] in state and n is not None and len(p)==3: state[key]=state[src[0]]+(n if m=='add' else -n); return
            if m=='mov' and len(p)==2 and r:
                src=reg(p[1],True)
                if src and src[0] in state: state[key]=state[src[0]]; return
            if m.startswith(('st','ld')):
                mem=next((x for x in p if '[' in x),'')
                parts=operands(mem.strip('[]!'))
                if parts:
                    base=reg(parts[0],True)
                    if base and base[0] in state:
                        if mem.endswith('!') and len(parts)>1 and number(parts[1]) is not None: state[base[0]]+=number(parts[1])
                        elif p[-1].startswith('#') and number(p[-1]) is not None: state[base[0]]+=number(p[-1])
                if m.startswith('st'): return
        else:
            if m=='push':
                if self.sp in state: state[self.sp]-=self.bits//8
                return
            if m=='pop':
                if self.sp in state: state[self.sp]+=self.bits//8
                state.pop(key,None); return
            if m=='leave':
                if self.fp in state: state[self.sp]=state[self.fp]+self.bits//8
                state.pop(self.fp,None); return
            if m=='mov' and len(p)==2 and r:
                src=reg(p[1],False)
                if src and src[0] in state: state[key]=state[src[0]]; return
            if m in ('add','sub') and len(p)==2 and key in state and number(p[1]) is not None:
                state[key]+=number(p[1])*(1 if m=='add' else -1); return
            if m in ('cmp','test','call','jmp') or m.startswith('j'): return
        if r and not m.startswith(('b.','cb','tb')): state.pop(key,None)

    def start(self,b):
        self.b=b; self.env={}; self.prepared=set(); self.flags=None; self.frame=dict(self.frame_states.get(b.start,{})); self.current=None

    def temp(self,bits,expr,kind='assign',detail=''):
        self.counter+=1; name='v%d'%self.counter; self.widths[name]=bits
        self.b.ops.append(Op(kind,name,expr,{self.addr},detail)); return V(name,bits)

    def readkey(self,key,bits=None):
        bits=bits or (1 if key.startswith('flag_') else self.bits)
        if key not in self.env:
            self.b.inputs.add(key); self.widths[key]=bits; self.env[key]=self.temp(bits,V(key,bits))
        return self.env[key]

    def readreg(self,s):
        r=reg(s,self.arm)
        if not r: raise ValueError('unsupported register '+s)
        key,bits,shift=r
        if key=='zero': return C(0,bits)
        e=self.readkey(key)
        if shift: e=X('>>',e,C(shift),bits=self.bits)
        return cast(e,bits)

    def write(self,s,e):
        r=reg(s,self.arm)
        if not r: raise ValueError('unsupported destination '+s)
        key,bits,shift=r
        if key=='zero': return
        e=cast(e,bits)
        if not self.arm and bits<32:
            mask=((1<<bits)-1)<<shift
            e=X('|',X('&',self.readkey(key),C(((1<<self.bits)-1)^mask),bits=self.bits),X('<<',cast(e,self.bits),C(shift),bits=self.bits),bits=self.bits)
        elif bits<self.bits: e=cast(e,self.bits)
        self.env[key]=self.temp(self.bits,e.at(self.addr)); self.b.outputs.add(key); self.prepared.add(key)

    def setflag(self,key,e):
        self.env[key]=self.temp(1,e.at(self.addr)); self.b.outputs.add(key)

    def setflags(self,l,r,op,bits,preserve_carry=False):
        l=cast(l,bits); r=cast(r,bits)
        result=cast(X(op,l,r,bits=bits),bits)
        self.flags=None if preserve_carry else (l.at(self.addr),r.at(self.addr),op,bits)
        self.setflag('flag_z',X('==',result,C(0,bits),bits=1))
        self.setflag('flag_n',X('<',cast(result,bits,True),C(0,bits),bits=1))
        if op in ('&','|','^'):
            if not preserve_carry: self.setflag('flag_c',C(0,1))
            self.setflag('flag_v',C(0,1))
        else:
            if not preserve_carry:
                carry=X('>=',l,r,bits=1) if op=='-' and self.arm else (X('<',l,r,bits=1) if op=='-' else X('<',result,l,bits=1))
                self.setflag('flag_c',carry)
            # Overflow is a bit identity, not C signed-overflow arithmetic.
            xor1=X('^',l,r,bits=bits); xor2=X('^',l,result,bits=bits)
            overflow=X('&',X('&',X('inv',xor1,bits=bits) if op=='+' else xor1,xor2,bits=bits),C(1<<(bits-1),bits),bits=bits)
            self.setflag('flag_v',X('!=',overflow,C(0,bits),bits=1))

    def condition(self,cc):
        cc=cc.lower().replace('b.',''); cc={'z':'eq','nz':'ne','e':'eq','l':'lt','g':'gt','le':'le','ge':'ge','ae':'hs','b':'lo','a':'hi','be':'ls','nb':'hs','na':'ls','nbe':'hi','nae':'lo','c':'lo' if not self.arm else 'hs','nc':'hs' if not self.arm else 'lo','cs':'hs','cc':'lo'}.get(cc,cc)
        if self.flags:
            l,r,op,bits=self.flags
            if op=='-' and cc in ('eq','ne','lt','le','gt','ge','hs','lo','hi','ls'):
                symbol={'eq':'==','ne':'!=','lt':'<','le':'<=','gt':'>','ge':'>=','hs':'>=','lo':'<','hi':'>','ls':'<='}[cc]
                if cc in ('lt','le','gt','ge'): l=cast(l,bits,True); r=cast(r,bits,True)
                return X(symbol,l,r,bits=1)
        z=lambda:self.readkey('flag_z',1); n=lambda:self.readkey('flag_n',1); c=lambda:self.readkey('flag_c',1); v=lambda:self.readkey('flag_v',1)
        neg=lambda x:X('not',x,bits=1)
        carry=c() if cc in ('hs','lo','hi','ls') else None
        if cc in ('hs','lo','hi','ls') and not self.arm: carry=neg(carry)
        rules={'eq':lambda:z(),'ne':lambda:neg(z()),'lt':lambda:X('!=',n(),v(),bits=1),'ge':lambda:X('==',n(),v(),bits=1),
               'gt':lambda:X('&&',neg(z()),X('==',n(),v(),bits=1),bits=1),'le':lambda:X('||',z(),X('!=',n(),v(),bits=1),bits=1),
               'hs':lambda:carry,'lo':lambda:neg(carry),'hi':lambda:X('&&',carry,neg(z()),bits=1),'ls':lambda:X('||',neg(carry),z(),bits=1),
               'mi':lambda:n(),'s':lambda:n(),'pl':lambda:neg(n()),'ns':lambda:neg(n()),'vs':lambda:v(),'o':lambda:v(),'vc':lambda:neg(v()),'no':lambda:neg(v())}
        if cc in rules: return rules[cc]()
        self.unsupported.add(self.addr)
        self.warning('Parity or uncommon conditions remain explicit machine-state intrinsics.')
        return E('unknown',bits=1,value='condition_'+cc).at(self.addr)

    def atom(self,s,bits=None):
        r=reg(s,self.arm)
        if r: return self.readreg(s)
        n=number(s)
        if n is not None: return C(n,bits or self.bits)
        if '[' in s: return self.load(s,bits or self.memwidth(s))
        raise ValueError('unrecognized operand '+s)

    def memwidth(self,s):
        match=re.search(r'\b(byte|word|dword|qword|xmmword|ymmword) ptr',s)
        return {'byte':8,'word':16,'dword':32,'qword':64,'xmmword':128,'ymmword':256}.get(match[1],self.bits) if match else self.bits

    def address(self,s):
        if not self.arm and re.search(r'\b(?:fs|gs|cs|ds|es|ss):',s): raise ValueError('segment-relative memory requires explicit segment state')
        inside=s[s.index('[')+1:s.index(']')]
        affine=None
        if self.arm:
            p=operands(inside); base=reg(p[0],True)
            if not base: raise ValueError('unknown memory base')
            e=self.readreg(p[0]); off=number(p[1]) if len(p)>1 else 0
            if off is not None:
                if base[0] in self.frame: affine=self.frame[base[0]]+off
                e=X('+',e,C(off),bits=64)
            else:
                idx=self.readreg(p[1])
                if len(p)>2:
                    mod=p[2].split(); amount=number(mod[1]) if len(mod)>1 else 0
                    if mod[0] in ('sxtw','sxtx'): idx=cast(cast(idx,32 if mod[0]=='sxtw' else 64,True),64)
                    elif mod[0]=='uxtw': idx=cast(cast(idx,32),64)
                    elif mod[0]!='lsl': raise ValueError('unknown indexed extension')
                    idx=X('<<',idx,C(amount or 0),bits=64)
                e=X('+',e,idx,bits=64)
            return e,affine
        # Intel syntax, scaled index plus displacement. Never evaluate text as code.
        tokens=re.findall(r'[+-]?\s*[^+-]+',inside); parts=[]; const=0; affine_terms=[]
        for token in tokens:
            token=token.replace(' ',''); sign=-1 if token.startswith('-') else 1; token=token.lstrip('+-')
            if '*' in token:
                r,scale=token.split('*')
                if number(r) is not None: r,scale=scale,r
                n=number(scale)
                if reg(r,False) is None or n not in (1,2,4,8): raise ValueError('invalid scaled address')
                val=X('*',self.readreg(r),C(n),bits=self.bits); affine_terms.append(None)
            elif token in ('rip','eip'):
                val=C(self.addr+len(bytes.fromhex(self.current.get('bytes',''))),self.bits); affine_terms.append(None)
            elif reg(token,False):
                val=self.readreg(token); affine_terms.append(self.frame.get(reg(token,False)[0]))
            elif number(token) is not None:
                n=number(token); val=C(n,self.bits); const+=sign*n
            else: raise ValueError('invalid memory term '+token)
            parts.append((sign,val))
        e=C(0,self.bits)
        for sign,val in parts: e=X('+' if sign>0 else '-',e,val,bits=self.bits)
        if len(affine_terms)==1 and affine_terms[0] is not None: affine=affine_terms[0]+const
        return e,affine

    def slot(self,off,bits):
        name=('stack_arg_%x'%off if off>=0 else 'local_%x'%-off)+'_u%d'%bits
        key=(off,bits)
        self.slots.setdefault(key,dict(name=name,bits=bits,offset=off,addresses=set()))['addresses'].add(self.addr)
        self.widths[name]=max(self.widths.get(name,0),bits)
        return name

    def load(self,s,bits,signed=False):
        addr,off=self.address(s)
        if off is not None:
            name=self.slot(off,bits)
            expr=cast(V(name,bits),bits,True) if signed else V(name,bits)
            if off>=0: self.stack_inputs[name]=bits
        else: expr=E('load',(addr,),bits,value=signed)
        # Loads retain a sequence point until a proven single-use substitution.
        return self.temp(bits,expr.at(self.addr),'load')

    def store(self,s,value,bits):
        addr,off=self.address(s); value=cast(value,bits)
        if off is not None: self.b.ops.append(Op('stack',self.slot(off,bits),value,{self.addr}))
        else: self.b.ops.append(Op('store','',value,{self.addr},str(bits),args=[addr]))

    def dest(self,s,e,bits=None):
        if reg(s,self.arm): self.write(s,e)
        elif '[' in s: self.store(s,e,bits or self.memwidth(s))
        else: raise ValueError('unsupported destination')

    def call(self,p,tail=False):
        target=number(self.current.get('target','')); name=''; prototype=''
        if target is not None:
            sym=next((f for f in self.a.get('functions',[]) if number(f['address'])==target),None)
            if sym: name=ident(sym['name']); prototype=ident(sym.get('semanticName',sym['name']))
            if not name or (name.startswith(('stubs','sub_')) and (not sym or sym.get('nameSource')!='analyst')):
                found=next((s for s in self.a.get('symbols',[]) if number(s['address'])==target and target),None)
                if found: name=ident(found['name']); prototype=name
            if not name: name='sub_%x'%target
            callee=E('function',value=name)
        else: callee=self.atom(p[0])
        # Unknown prototypes: only include the contiguous argument registers
        # prepared in this block. Signature recovery is explicitly heuristic.
        args=[]
        known={'strlen':1,'puts':1,'strcmp':2,'strncmp':3,'memcpy':3,'memset':3,'memcmp':3,'malloc':1,'free':1,'sleep':1,'printf':1,'fprintf':2,'strcpy':2,'strncpy':3}
        minimum=known.get(prototype,0)
        for idx,key in enumerate(self.argregs):
            if idx>=minimum and (key not in self.prepared or (prototype in known and prototype not in ('printf','fprintf'))): break
            args.append(self.readkey(key))
            if key in self.frame: self.stack_escaped=True
        self.warning('Call prototypes and register arguments are inferred; varargs, stack arguments and nonstandard conventions may be incomplete.')
        self.counter+=1; dst='call_%d'%self.counter; self.widths[dst]=self.bits
        self.b.ops.append(Op('call',dst,callee,{self.addr},'tail' if tail else '',target,args))
        for key in self.caller:
            self.env[key]=E('unknown',bits=self.bits,value=key+'_after_call').at(self.addr); self.b.outputs.add(key)
        for key in ('flag_z','flag_n','flag_c','flag_v'):
            self.env[key]=E('unknown',bits=1,value=key+'_after_call').at(self.addr); self.b.outputs.add(key)
        self.env[self.ret]=V(dst,self.bits); self.flags=None; self.prepared.clear()
        if tail: self.b.term=Op('return',expr=V(dst,self.bits),origins={self.addr})

    def opaque(self,i,why):
        self.unsupported.add(self.addr)
        # Materialize inputs before the opaque barrier and invalidate outputs.
        # No value is propagated through an instruction with unknown effects.
        self.b.ops.append(Op('opaque',origins={self.addr},detail=i['mnemonic']+' '+i['operands']))
        for key in set(self.env)|set(self.caller)|{'flag_z','flag_n','flag_c','flag_v'}:
            self.env[key]=E('unknown',bits=self.widths.get(key,self.bits),value=key+'_after_%x'%self.addr).at(self.addr); self.b.outputs.add(key)
        self.flags=None
        self.warning('Unsupported instructions invalidate register/flag assumptions and remain explicit asm_effect statements.')

    def lift(self):
        for b in self.blocks:
            self.start(b)
            for i in b.ins:
                self.current=i; self.addr=int(i['address'],16)
                p=operands(i['operands']); m=i['mnemonic'].lower()
                mark=len(b.ops); old=dict(self.env); oldout=set(b.outputs); oldflags=self.flags
                try:
                    if self.arm: self.armop(m,p)
                    else: self.x86op(m,p)
                except (ValueError,IndexError,KeyError,TypeError):
                    del b.ops[mark:]; self.env=old; b.outputs=oldout; self.flags=oldflags
                    self.opaque(i,'unsupported operand or instruction')
                self.frame_step(self.frame,i)
            b.env=dict(self.env)
            if b.term is None:
                b.term=Op('jump',target=b.succ[0]) if b.succ else Op('end',detail='Function boundary; no return was decoded')
        return self

    def armop(self,m,p):
        if m in ('nop','bti','paciasp','pacibsp','autiasp','autibsp','xpaclri'):
            # Authentication is not treated as scalar arithmetic, but kept visible.
            self.b.ops.append(Op('mechanic',origins={self.addr},detail=' '.join([m]+p))); return
        if m in ('ret','retaa','retab'):
            self.b.term=Op('return',expr=self.readkey(self.ret),origins={self.addr}); return
        if m in ('bl','blr','blraa','blrab'):
            if m not in ('bl','blr'): raise ValueError('authenticated call')
            self.call(p); return
        if m in ('b','br'):
            target=number(self.current.get('target',''))
            self.b.term=Op('jump',expr=self.atom(p[0]) if target is None else None,target=target,origins={self.addr}); return
        if m.startswith('b.'):
            self.b.term=Op('branch',expr=self.condition(m[2:]).at(self.addr),target=number(self.current.get('target','')),origins={self.addr}); return
        if m in ('cbz','cbnz','tbz','tbnz'):
            e=self.atom(p[0])
            if m.startswith('tb'): e=X('&',e,C(1<<number(p[1]),e.bits),bits=e.bits)
            cond=X('==' if m.endswith('z') and m not in ('cbnz','tbnz') else '!=',e,C(0,e.bits),bits=1)
            self.b.term=Op('branch',expr=cond.at(self.addr),target=number(self.current.get('target','')),origins={self.addr}); return
        if m in ('brk','hlt','svc'):
            self.opaque(self.current,'system operation')
            if m in ('brk','hlt'): self.b.term=Op('end',origins={self.addr},detail='Trap; execution does not fall through')
            else: self.flags=None
            return
        if m in ('mov','movz','movn','movk'):
            bits=reg(p[0],True)[1]; e=self.atom(p[1],bits)
            shift=number(p[2].split()[-1]) if len(p)>2 else 0
            if shift: e=X('<<',e,C(shift),bits=bits)
            if m=='movn': e=X('inv',e,bits=bits)
            if m=='movk': e=X('|',X('&',self.readreg(p[0]),C(((1<<bits)-1)^(0xffff<<shift),bits),bits=bits),e,bits=bits)
            self.write(p[0],e); return
        if m in ('adr','adrp'):
            self.write(p[0],C(number(p[1]),64)); return
        if m in ('cmp','cmn','tst'):
            l=self.atom(p[0]); r=self.atom(p[1],l.bits)
            if len(p)>2: r=self.shift_operand(r,p[2],l.bits)
            self.setflags(l,r,{'cmp':'-','cmn':'+','tst':'&'}[m],l.bits); return
        binary={'add':'+','adds':'+','sub':'-','subs':'-','mul':'*','and':'&','ands':'&','orr':'|','eor':'^','lsl':'<<','lsr':'>>','asr':'>>','sdiv':'/','udiv':'/','bic':'&','orn':'|','eon':'^'}
        if m in binary:
            bits=reg(p[0],True)[1]; l=self.atom(p[1],bits); r=self.atom(p[2],bits)
            if len(p)>3: r=self.shift_operand(r,p[3],bits)
            if m in ('bic','orn','eon'): r=X('inv',r,bits=bits)
            if m in ('asr','sdiv'): l=cast(l,bits,True)
            if m=='sdiv': r=cast(r,bits,True)
            if m in ('sdiv','udiv'): expr=X('intrinsic',l,r,bits=bits,value=('sdiv' if m=='sdiv' else 'udiv')+str(bits))
            else: expr=X(binary[m],l,r,bits=bits)
            if m in ('adds','subs','ands'): self.setflags(l,r,binary[m],bits)
            self.write(p[0],expr); return
        if m in ('madd','msub','mneg'):
            bits=reg(p[0],True)[1]; mul=X('*',self.atom(p[1]),self.atom(p[2]),bits=bits)
            expr=X('neg',mul,bits=bits) if m=='mneg' else X('+' if m=='madd' else '-',self.atom(p[3]),mul,bits=bits)
            self.write(p[0],expr); return
        if m in ('neg','negs','mvn'):
            e=self.atom(p[1]); bits=reg(p[0],True)[1]
            if m=='negs': self.setflags(C(0,bits),e,'-',bits)
            self.write(p[0],X('inv' if m=='mvn' else 'neg',e,bits=bits)); return
        if m in ('sxtb','sxth','sxtw','uxtb','uxth'):
            bits={'sxtb':8,'sxth':16,'sxtw':32,'uxtb':8,'uxth':16}[m]
            self.write(p[0],cast(self.atom(p[1]),bits,m.startswith('s'))); return
        if m in ('csel','csinc','csinv','csneg','cset','csetm','cinc','cinv','cneg'):
            bits=reg(p[0],True)[1]
            if m in ('cset','csetm'):
                cond=self.condition(p[1]); l=C((1<<bits)-1 if m=='csetm' else 1,bits); r=C(0,bits)
            elif m in ('cinc','cinv','cneg'):
                cond=self.condition(p[2]); r=self.atom(p[1]); l=X('+',r,C(1,bits),bits=bits) if m=='cinc' else X('inv' if m=='cinv' else 'neg',r,bits=bits)
            else:
                cond=self.condition(p[3]); l=self.atom(p[1]); r=self.atom(p[2])
                if m=='csinc': r=X('+',r,C(1,bits),bits=bits)
                elif m in ('csinv','csneg'): r=X('inv' if m=='csinv' else 'neg',r,bits=bits)
            self.write(p[0],X('select',cond,l,r,bits=bits)); return
        if m.startswith(('ldr','ldur','str','stur')) and m in ('ldr','ldur','ldrb','ldurb','ldrh','ldurh','ldrsb','ldursb','ldrsh','ldursh','ldrsw','ldursw','str','stur','strb','sturb','strh','sturh'):
            bits=reg(p[0],True)[1]
            if m.endswith('b'): bits=8
            elif m.endswith('h'): bits=16
            elif m.endswith('sw'): bits=32
            if '[' not in p[1]: raise ValueError('literal memory load')
            if m.startswith('ld'): self.write(p[0],self.load(p[1],bits,'s' in m[3:]))
            else: self.store(p[1],self.atom(p[0]),bits)
            self.writeback(p,1); return
        if m in ('stp','ldp','ldpsw'):
            bits=reg(p[0],True)[1] if m!='ldpsw' else 32
            mem=p[2]; addr,off=self.address(mem)
            # Save/restore of FP/LR is retained as bookkeeping, not user locals.
            if p[0] in ('x29','fp') and p[1] in ('x30','lr'):
                self.b.ops.append(Op('mechanic',origins={self.addr},detail=m+' '+', '.join(p)))
            else:
                for n,d in enumerate(p[:2]):
                    ad=X('+',addr,C(n*bits//8),bits=64); slot=self.slot(off+n*bits//8,bits) if off is not None else None
                    if m.startswith('ld'):
                        e=V(slot,bits) if slot else E('load',(ad,),bits,value=m=='ldpsw')
                        self.write(d,self.temp(bits,e.at(self.addr),'load'))
                    elif slot: self.b.ops.append(Op('stack',slot,cast(self.atom(d),bits),{self.addr}))
                    else: self.b.ops.append(Op('store','',cast(self.atom(d),bits),{self.addr},str(bits),args=[ad]))
            self.writeback(p,2); return
        raise ValueError('unsupported ARM64 mnemonic')

    def shift_operand(self,e,s,bits):
        parts=s.split(); kind=parts[0]; amount=number(parts[1]) if len(parts)>1 else 0
        if kind in ('uxtb','uxth','uxtw','uxtx','sxtb','sxth','sxtw','sxtx'):
            e=cast(cast(e,{'b':8,'h':16,'w':32,'x':64}[kind[-1]],kind.startswith('s')),bits); kind='lsl'
        if kind not in ('lsl','lsr','asr'): raise ValueError('unsupported shift')
        if kind=='asr': e=cast(e,bits,True)
        return X('<<' if kind=='lsl' else '>>',e,C(amount or 0),bits=bits)

    def writeback(self,p,index):
        mem=p[index]; parts=operands(mem.strip('[]!')); base=parts[0]
        if mem.endswith('!') and len(parts)>1: self.write(base,X('+',self.readreg(base),self.atom(parts[1]),bits=64))
        elif len(p)>index+1: self.write(base,X('+',self.readreg(base),self.atom(p[index+1]),bits=64))

    def x86op(self,m,p):
        if m in ('nop','nopl','nopw','endbr64','endbr32'):
            self.b.ops.append(Op('mechanic',origins={self.addr},detail=m+' '+', '.join(p))); return
        if m in ('ret','retq','retn'):
            self.b.term=Op('return',expr=self.readkey(self.ret),origins={self.addr}); return
        if m in ('call','callq'): self.call(p); return
        if m in ('jmp','jmpq'):
            target=number(self.current.get('target',''))
            self.b.term=Op('jump',target=target,expr=self.atom(p[0]) if target is None else None,origins={self.addr}); return
        if m.startswith('j') and m not in ('jmp','jmpq'):
            if m in ('jrcxz','jecxz','jcxz'): cond=X('==',self.readreg({'jrcxz':'rcx','jecxz':'ecx','jcxz':'cx'}[m]),C(0),bits=1)
            else: cond=self.condition(m[1:])
            self.b.term=Op('branch',expr=cond.at(self.addr),target=number(self.current.get('target','')),origins={self.addr}); return
        if m in ('ud2','hlt','int3'):
            self.b.ops.append(Op('opaque',origins={self.addr},detail=m)); self.unsupported.add(self.addr)
            self.b.term=Op('end',origins={self.addr},detail='Trap; execution does not fall through'); return
        if m=='push':
            # Canonical stack slots retain saved registers and pushed arguments.
            self.write('rsp' if self.bits==64 else 'esp',X('-',self.readkey(self.sp),C(self.bits//8),bits=self.bits))
            off=self.frame.get(self.sp)
            if p[0] in ('rbp','ebp'):
                self.b.ops.append(Op('mechanic',origins={self.addr},detail='save frame pointer'))
            elif off is not None: self.b.ops.append(Op('stack',self.slot(off-self.bits//8,self.bits),self.atom(p[0]),{self.addr}))
            else: self.b.ops.append(Op('store','',self.atom(p[0]),{self.addr},str(self.bits),args=[self.readkey(self.sp)]))
            return
        if m=='pop':
            if p[0] not in ('rbp','ebp'): self.write(p[0],self.load('[rsp]' if self.bits==64 else '[esp]',self.bits))
            else: self.b.ops.append(Op('mechanic',origins={self.addr},detail='restore frame pointer'))
            self.write('rsp' if self.bits==64 else 'esp',X('+',self.readkey(self.sp),C(self.bits//8),bits=self.bits)); return
        if m=='leave':
            self.write('rsp' if self.bits==64 else 'esp',X('+',self.readkey(self.fp),C(self.bits//8),bits=self.bits))
            self.b.ops.append(Op('mechanic',origins={self.addr},detail='restore stack frame')); return
        if m in ('mov','movabs','movzx','movsx','movsxd','lea'):
            bits=reg(p[0],False)[1] if reg(p[0],False) else self.memwidth(p[0])
            if m=='lea': e=self.address(p[1])[0]
            else:
                sourcebits=self.memwidth(p[1]) if '[' in p[1] else (reg(p[1],False)[1] if reg(p[1],False) else bits)
                e=self.atom(p[1],sourcebits)
                if m in ('movsx','movsxd'): e=cast(e,sourcebits,True)
            self.dest(p[0],e,bits); return
        if m in ('cmp','test'):
            bits=reg(p[0],False)[1] if reg(p[0],False) else self.memwidth(p[0])
            self.setflags(self.atom(p[0],bits),self.atom(p[1],bits),'-' if m=='cmp' else '&',bits); return
        if m in ('add','sub','and','or','xor','shl','sal','shr','sar','imul','inc','dec','neg','not'):
            bits=reg(p[0],False)[1] if reg(p[0],False) else self.memwidth(p[0])
            if m=='imul' and len(p)==1: raise ValueError('full width multiply')
            l=self.atom(p[1] if m=='imul' and len(p)==3 else p[0],bits)
            r=self.atom(p[-1],bits) if len(p)>1 else C(1,bits)
            if m in ('shl','sal','shr','sar'): r=X('&',r,C(63 if bits==64 else 31),bits=bits)
            if m=='sar': l=cast(l,bits,True)
            op={'add':'+','inc':'+','sub':'-','dec':'-','and':'&','or':'|','xor':'^','shl':'<<','sal':'<<','shr':'>>','sar':'>>','imul':'*','neg':'-','not':'inv'}[m]
            if m=='neg': r=l; l=C(0,bits)
            expr=X('inv',l,bits=bits) if m=='not' else X(op,l,r,bits=bits)
            if m in ('add','sub','and','or','xor','inc','dec','neg'): self.setflags(l,r,op,bits,m in ('inc','dec'))
            elif m!='not':
                self.flags=None
                for key in ('flag_z','flag_n','flag_c','flag_v'):
                    self.env[key]=E('unknown',bits=1,value=key+'_after_'+m).at(self.addr); self.b.outputs.add(key)
            self.dest(p[0],expr,bits); return
        if m.startswith('set'):
            self.dest(p[0],cast(self.condition(m[3:]),8),8); return
        if m.startswith('cmov'):
            bits=reg(p[0],False)[1]
            # Memory operand is evaluated even when condition is false.
            other=self.atom(p[1],bits)
            self.write(p[0],X('select',self.condition(m[4:]),other,self.atom(p[0]),bits=bits)); return
        if m in ('cdqe','cwde','cbw'):
            self.write({'cdqe':'rax','cwde':'eax','cbw':'ax'}[m],cast(self.readreg({'cdqe':'eax','cwde':'ax','cbw':'al'}[m]),{'cdqe':32,'cwde':16,'cbw':8}[m],True)); return
        if m in ('cdq','cqo'):
            bits=64 if m=='cqo' else 32
            self.write('rdx' if bits==64 else 'edx',X('>>',cast(self.readreg('rax' if bits==64 else 'eax'),bits,True),C(bits-1),bits=bits)); return
        if m=='xchg' and all(reg(s,False) for s in p):
            l=self.atom(p[0]); r=self.atom(p[1]); self.write(p[0],r); self.write(p[1],l); return
        if m=='bswap':
            e=self.atom(p[0]); self.write(p[0],X('intrinsic',e,bits=e.bits,value='bswap%d'%e.bits)); return
        raise ValueError('unsupported x86 mnemonic')


def analyze_liveness(blocks):
    by={b.start:b for b in blocks}
    def dependencies(b, expressions):
        definitions={op.dst:op.expr for op in b.ops if op.dst and op.kind in ('assign','load')}
        result=set(); pending=set().union(*(e.refs() for e in expressions if e)); seen=set()
        while pending:
            key=pending.pop()
            if key in seen: continue
            seen.add(key)
            if key in definitions: pending |= definitions[key].refs()
            elif key in b.inputs: result.add(key)
        return result
    roots={b.start:[e for op in b.ops+[b.term] if op.kind not in ('assign','mechanic') for e in ([op.expr]+op.args) if e] for b in blocks}
    for _ in range(len(blocks)*4+1):
        changed=False
        for b in reversed(blocks):
            out=set().union(*(by[s].livein for s in b.succ)) if b.succ else set()
            incoming=dependencies(b,roots[b.start]+[b.env[k] for k in out & b.outputs]) | (out-b.outputs)
            if out!=b.liveout or incoming!=b.livein: b.liveout=out; b.livein=incoming; changed=True
        if not changed: break
    for b in blocks:
        for key in sorted(b.outputs & b.liveout): b.ops.append(Op('output',key,b.env[key],set()))


def optimize(block):
    ops=block.ops
    # Single-use substitution keeps expression growth bounded. Calls, unknown
    # effects and memory writes are barriers to moving memory reads.
    for _ in range(12):
        counts=Counter()
        for op in ops+[block.term]:
            def visit(e):
                if e.op=='var': counts[e.value]+=1
                for a in e.args: visit(a)
            if op.expr: visit(op.expr)
            for e in op.args: visit(e)
        removed=set(); changed=False
        for idx,op in enumerate(ops):
            if op.kind not in ('assign','load') or not op.dst: continue
            count=counts[op.dst]
            if count==0 and not op.expr.effect():
                block.omitted |= op.sources(); removed.add(idx); changed=True; continue
            if count!=1: continue
            uses=[j for j,q in enumerate(ops+[block.term]) if op.dst in q.refs()]
            if len(uses)!=1 or uses[0]<=idx: continue
            j=uses[0]; consumer=(ops+[block.term])[j]
            between=ops[idx+1:j]
            # Do not inline mutable values across writes to those locations.
            refs=op.expr.refs()
            if any(q.dst in refs or q.kind=='opaque' for q in between): continue
            if (op.kind=='load' or op.expr.effect()) and any(q.barrier() or q.kind=='load' or (q.expr and q.expr.effect()) for q in between): continue
            if op.expr.effect() and consumer.expr and contains_lazy(consumer.expr): continue
            if expression_size(op.expr)>90: continue
            consumer.substitute(op.dst,op.expr.at(*op.origins)); removed.add(idx); changed=True
        if removed: ops=[op for i,op in enumerate(ops) if i not in removed]
        if not changed: break
    block.ops=ops


def contains_lazy(e): return e.op in ('select','&&','||') or any(contains_lazy(a) for a in e.args)


def expression_size(e): return 1+sum(expression_size(a) for a in e.args)


def dominators(blocks,post=False):
    by={b.start:b for b in blocks}; keys=set(by); root=blocks[0].start
    if post:
        # Synthetic exit distinguishes return nodes and loop-only regions.
        exitnode=-1; keys=keys|{exitnode}; incoming={b.start:set(b.succ) or {exitnode} for b in blocks}; incoming[exitnode]=set(); root=exitnode
    else: incoming={b.start:set(b.pred) for b in blocks}
    d={k:({k} if k==root else set(keys)) for k in keys}
    for _ in range(len(keys)*3):
        changed=False
        for k in sorted(keys):
            if k==root: continue
            predecessors=incoming[k]
            new={k}|(set.intersection(*(d[p] for p in predecessors)) if predecessors else set())
            if new!=d[k]: d[k]=new; changed=True
        if not changed: break
    return d


def regions(blocks):
    by={b.start:b for b in blocks}; dom=dominators(blocks); post=dominators(blocks,True)
    loops={}
    for b in blocks:
        for h in b.succ:
            if h in dom[b.start]:
                members={h,b.start}; work=[b.start] if b.start!=h else []
                while work:
                    n=work.pop()
                    for p in by[n].pred:
                        if p not in members: members.add(p); work.append(p)
                loops.setdefault(h,set()).update(members)
    joins={}
    for b in blocks:
        candidates=post[b.start]-{b.start,-1}
        if candidates:
            joins[b.start]=max(candidates,key=lambda n:len(post[n]))
    return dom,post,loops,joins


def compact_regions(blocks):
    blocks=copy.deepcopy(blocks)
    entry=blocks[0].start
    def rebuild():
        by={b.start:b for b in blocks}
        for b in blocks: b.pred=set()
        for b in blocks:
            for n in b.succ:
                if n in by: by[n].pred.add(b.start)
        return by
    # Only eliminate nodes whose optimized semantics are a single jump.
    for _ in range(len(blocks)):
        by=rebuild(); changed=False
        for b in list(blocks):
            if b.start==entry or b.term.kind!='jump' or b.term.target==b.start or b.term.target not in by: continue
            if any(op.kind!='mechanic' for op in b.ops): continue
            for parent in blocks:
                if b.start in parent.succ:
                    parent.succ=list(dict.fromkeys(b.term.target if n==b.start else n for n in parent.succ))
                    if parent.term.target==b.start: parent.term.target=b.term.target
                    parent.term.origins |= b.term.sources() | set().union(*(op.sources() for op in b.ops))
            blocks.remove(b); changed=True; break
        if not changed: break
    # Fold proven short-circuit diamonds without moving effectful statements.
    for _ in range(len(blocks)):
        by=rebuild(); changed=False
        for a in list(blocks):
            if a.term.kind!='branch' or len(a.succ)!=2: continue
            at=a.term.target; af=next(n for n in a.succ if n!=at)
            for child,shared,ontrue in [(af,at,False),(at,af,True)]:
                b=by.get(child)
                if not b or b.start==entry or b.pred!={a.start} or b.term.kind!='branch' or len(b.succ)!=2 or any(op.kind!='mechanic' for op in b.ops): continue
                bt=b.term.target; bf=next(n for n in b.succ if n!=bt)
                if shared not in (bt,bf): continue
                if ontrue:
                    rhs=b.term.expr if bf==shared else X('not',b.term.expr,bits=1)
                    target=bt if bf==shared else bf; fall=shared; op='&&'
                else:
                    rhs=b.term.expr if bt==shared else X('not',b.term.expr,bits=1)
                    target=shared; fall=bf if bt==shared else bt; op='||'
                a.term.expr=X(op,a.term.expr,rhs,bits=1)
                a.term.origins |= b.term.sources()
                a.term.target=target; a.succ=[target,fall]
                blocks.remove(b); changed=True; break
            if changed: break
        if not changed: break
    rebuild()
    return blocks


class Renderer:
    def __init__(self,a,lifter,names=None):
        self.a=a; self.lifter=lifter; self.blocks=compact_regions(lifter.blocks); self.by={b.start:b for b in self.blocks}
        self.names=names or {}; self.lines=[]; self.emitted=set(); self.dom,self.post,self.loops,self.joins=regions(self.blocks)
        self.instructions={int(i['address'],16):i for b in lifter.blocks for i in b.ins}
        self.structured_loops=0; self.structured_ifs=0

    def line(self,text,origins=(),indent=1,kind='statement',explanation='Lifted instruction semantics'):
        if 'unknown_' in text and kind not in ('unsupported','mechanic','comment'):
            kind='uncertain'; explanation='Contains unrecovered machine state; inspect diagnostics and the contributing instructions'
        addresses=sorted(set(origins)&set(self.instructions)); spans=[]
        for addr in addresses:
            i=self.instructions[addr]; size=len(bytes.fromhex(i.get('bytes','')))
            if i['offset']<0 or not size: continue
            spans.append(dict(address=hex(addr),offset=i['offset'],size=size,bytes=i['bytes']))
        self.lines.append(dict(id=len(self.lines),text='    '*indent+text,kind=kind,
                               addresses=[hex(n) for n in addresses],spans=spans,explanation=explanation))

    def op(self,op,indent):
        text=lambda e:e.text(self.names)
        if op.kind in ('assign','load','output','stack'):
            self.line('%s = %s;'%(self.names.get(op.dst,op.dst),text(op.expr)),op.sources(),indent,
                      explanation='Value and its contributing definitions; integer widths are explicit')
        elif op.kind=='store': self.line('store_u%s(%s, %s);'%(op.detail,text(op.args[0]),text(op.expr)),op.sources(),indent,explanation='Memory write; helper suffix specifies access width in bits')
        elif op.kind=='call':
            if op.target is None:
                call='indirect_call(%s)'%', '.join([text(op.expr)]+[text(e) for e in op.args])
            else: call='%s(%s)'%(text(op.expr),', '.join(text(e) for e in op.args))
            self.line('%s = %s;'%(self.names.get(op.dst,op.dst),call),op.sources(),indent,'call','Call with inferred arguments; prototype may be incomplete')
        elif op.kind=='opaque': self.line('asm_effect(%s);'%json.dumps(op.detail),op.sources(),indent,'unsupported','Unsupported machine effects. Subsequent uncertain values are explicit unknown intrinsics.')
        elif op.kind=='mechanic': self.line('/* %s */'%op.detail.replace('*/','* /'),op.sources(),indent,'mechanic','Machine bookkeeping retained for byte-level traceability')

    def jump(self,target,indent,origins=(),loop=None):
        if loop and target==loop[0]: self.line('continue;',origins,indent,'control'); return
        if loop and target==loop[1]: self.line('break;',origins,indent,'control'); return
        self.line('goto loc_%x;'%target,origins,indent,'control','Unstructured edge preserved exactly')

    def emit(self,start,stop=None,indent=1,allowed=None,loop=None,depth=0):
        if depth>100:
            self.jump(start,indent); return
        cur=start
        while cur is not None and cur!=stop:
            if cur not in self.by:
                self.line('tail_jump(0x%x);'%cur,indent=indent,kind='unsupported',explanation='Target is outside the discovered function'); return
            if cur in self.emitted or (allowed is not None and cur not in allowed):
                self.jump(cur,indent,loop=loop); return
            b=self.by[cur]
            # A single-entry natural loop with exactly one outside successor.
            members=self.loops.get(cur)
            exits={s for n in members for s in self.by[n].succ if s not in members} if members else set()
            external_entries={n for n in members if n!=cur and any(p not in members for p in self.by[n].pred)} if members else set()
            if members and len(exits)==1 and not external_entries and (not loop or cur!=loop[0]) and (allowed is None or members<=allowed):
                exitaddr=next(iter(exits)); self.structured_loops+=1
                self.line('loc_%x:'%cur,indent=max(0,indent-1),kind='label')
                self.line('while (true) {',indent=indent,kind='control',explanation='Natural loop identified by a dominating header and back edge')
                self.emit(cur,None,indent+1,members,(cur,exitaddr),depth+1)
                self.line('}',indent=indent,kind='control')
                cur=exitaddr; continue
            self.emitted.add(cur)
            self.line('loc_%x:'%cur,indent=max(0,indent-1),kind='label')
            for op in b.ops: self.op(op,indent)
            t=b.term
            if t.kind=='return':
                self.line('return %s;'%t.expr.text(self.names),t.sources(),indent,'return'); return
            if t.kind=='end':
                self.line('/* %s */'%t.detail,t.sources(),indent,'unsupported'); return
            if t.kind=='jump':
                if t.target is None:
                    self.line('indirect_jump(%s);'%(t.expr.text(self.names) if t.expr else 'unknown_target()'),t.sources(),indent,'unsupported','Indirect targets are unresolved'); return
                if t.target==stop:
                    if t.sources(): self.line('/* join */',t.sources(),indent,'mechanic')
                    return
                if loop and t.target in loop:
                    self.jump(t.target,indent,t.sources(),loop); return
                if t.target in self.emitted or (allowed is not None and t.target not in allowed):
                    self.jump(t.target,indent,t.sources(),loop); return
                if t.sources(): self.line('/* fall through to loc_%x */'%t.target,t.sources(),indent,'mechanic')
                cur=t.target; continue
            if t.kind=='branch':
                target=t.target; fall=next((s for s in b.succ if s!=target),None)
                # Duplicate edges still evaluate the flags but don't alter flow.
                if len(b.succ)==1 and target==b.succ[0]:
                    self.line('/* both outcomes reach loc_%x */'%target,t.sources(),indent,'mechanic'); cur=target; continue
                if fall is None:
                    self.line('if (%s) tail_jump(%s);'%(t.expr.text(self.names),hex(target) if target is not None else 'unknown_target()'),t.sources(),indent,'unsupported'); return
                # Common loop exits/back edges get direct break/continue.
                if loop and (target in loop or fall in loop):
                    chosen=target if target in loop else fall; other=fall if chosen==target else target
                    cond=t.expr if chosen==target else X('not',t.expr,bits=1)
                    self.line('if (%s) {'%cond.text(self.names),t.sources(),indent,'control')
                    self.jump(chosen,indent+1,(),loop); self.line('}',indent=indent,kind='control')
                    self.structured_ifs+=1; cur=other; continue
                join=self.joins.get(cur)
                if join in self.emitted: join=None
                if join is not None and (allowed is None or join in allowed or join==stop):
                    condition=t.expr
                    if target>fall:
                        target,fall=fall,target; condition=X('not',condition,bits=1)
                    self.line('if (%s) {'%condition.text(self.names),t.sources(),indent,'control')
                    self.emit(target,join,indent+1,allowed,loop,depth+1)
                    if fall!=join:
                        self.line('} else {',indent=indent,kind='control'); self.emit(fall,join,indent+1,allowed,loop,depth+1)
                    self.line('}',indent=indent,kind='control'); self.structured_ifs+=1
                    cur=join; continue
                # No proven join: keep the edge and retain fallthrough order.
                self.line('if (%s) {'%t.expr.text(self.names),t.sources(),indent,'control')
                if target is not None: self.jump(target,indent+1,(),loop)
                else: self.line('indirect_jump(unknown_target());',indent=indent+1,kind='unsupported')
                self.line('}',indent=indent,kind='control'); cur=fall; continue
            return

    def render(self,function,variables):
        args=[v for v in variables if v['kind']=='argument']
        self.line('/* Asteria %s · %s · inferred types; review diagnostics */'%(VERSION,self.lifter.abi),indent=0,kind='comment')
        self.line('uint%d_t %s(%s) {'%(self.lifter.bits,ident(function['name']),', '.join('%s %s'%(v['type'],self.names.get(v['name'],v['name'])) for v in args) or 'void'),indent=0,kind='signature')
        local=[v for v in variables if v['kind']!='argument']
        for v in local:
            self.line('%s %s; /* %s */'%(v['type'],self.names.get(v['name'],v['name']),v['storage']),indent=1,kind='declaration',explanation='Recovered storage; type reflects machine width, not original source type')
        self.emit(self.blocks[0].start)
        for b in self.blocks:
            if b.start not in self.emitted:
                self.line('/* Additional or unreachable region */',indent=1,kind='comment'); self.emit(b.start)
        covered={int(a,16) for line in self.lines for a in line['addresses']}
        remaining=set(self.instructions)-covered
        if remaining:
            # Explicit provenance for removed pure definitions/frame arithmetic.
            self.line('/* Compiler mechanics and unused pure definitions (%d instructions). */'%len(remaining),remaining,1,'mechanic','Instructions removed by local dead-value simplification, including frame arithmetic. Select to inspect every original byte.')
        self.line('}',indent=0,kind='control')
        # Remove labels with no explicit goto references for a readable default.
        used={int(m,16) for line in self.lines for m in re.findall(r'goto loc_([0-9a-f]+)',line['text'])}
        self.lines=[line for line in self.lines if line['kind']!='label' or int(re.search(r'loc_([0-9a-f]+)',line['text'])[1],16) in used]
        for n,line in enumerate(self.lines): line['id']=n
        return self.lines


def normalize_cdecl_arguments(lifter):
    if lifter.abi!='cdecl32': return
    for (off,bits),slot in list(lifter.slots.items()):
        if not 4<=off<=128 or bits>32 or (off%4)*8+bits>32: continue
        base=off//4*4; old=slot['name']; canonical='stack_arg_%x_u32'%base
        if old==canonical: continue
        shift=(off-base)*8; value=cast(X('>>',V(canonical,32),C(shift),bits=32),bits)
        for b in lifter.blocks:
            for op in b.ops+[b.term]:
                op.substitute(old,value)
                if op.kind=='stack' and op.dst==old:
                    mask=((1<<bits)-1)<<shift
                    op.dst=canonical
                    op.expr=X('|',X('&',V(canonical,32),C(0xffffffff^mask,32),bits=32),X('<<',cast(op.expr,32),C(shift),bits=32),bits=32)
        lifter.widths[canonical]=32
        del lifter.slots[(off,bits)]
        target=lifter.slots.setdefault((base,32),dict(name=canonical,bits=32,offset=base,addresses=set()))
        target['addresses'] |= slot['addresses']


def repair_stack_aliases(lifter):
    slots=list(lifter.slots)
    overlapping={slot for slot in slots if any(slot!=other and max(slot[0],other[0])<min(slot[0]+slot[1]//8,other[0]+other[1]//8) for other in slots)}
    if not overlapping: return
    lifter.warning('Overlapping stack accesses are shown through entry_stack memory; separate source variables cannot be proved.')
    for off,bits in overlapping:
        old=lifter.slots[(off,bits)]['name']
        addr=X('+',V('entry_stack',lifter.bits),C(off,lifter.bits),bits=lifter.bits)
        value=E('load',(addr,),bits,value=False)
        for b in lifter.blocks:
            for op in b.ops+[b.term]:
                if op.kind=='stack' and op.dst==old:
                    op.kind='store'; op.dst=''; op.args=[addr]; op.detail=str(bits)
                op.substitute(old,value)
        del lifter.slots[(off,bits)]


def recover_variables(lifter,names):
    variables=[]; used=set(); widths=dict(lifter.widths)
    for b in lifter.blocks:
        for op in b.ops+[b.term]:
            used|=op.refs()
            if op.dst: used.add(op.dst)
    # Function symbols are expressions but not local storage.
    functions={op.expr.value for b in lifter.blocks for op in b.ops if op.kind=='call' and op.expr.op=='var' and op.expr.value not in lifter.widths}
    used-=functions
    args=set(lifter.blocks[0].livein)&set(lifter.argregs)
    argindexes=[lifter.argregs.index(r) for r in args]
    if argindexes: args=set(lifter.argregs[:max(argindexes)+1])
    for key in sorted(args,key=lifter.argregs.index):
        name='arg%d'%(lifter.argregs.index(key)+1); names.setdefault(key,name)
        variables.append(dict(name=key,type='uint%d_t'%lifter.bits,kind='argument',storage=key,addresses=[]))
    slots={s['name']:s for s in lifter.slots.values()}
    if lifter.abi=='cdecl32':
        candidates=[s for s in slots.values() if s['name'] in used and s['offset']>=4 and s['offset']%4==0 and s['bits']==32]
        maximum=min(max((s['offset']//4 for s in candidates),default=0),32)
        for index in range(1,maximum+1):
            key='stack_arg_%x_u32'%(index*4); names.setdefault(key,'arg%d'%index); args.add(key)
            variables.append(dict(name=key,type='uint32_t',kind='argument',storage='entry SP + 0x%x'%(index*4),addresses=[hex(n) for n in sorted(slots.get(key,{}).get('addresses',set()))]))
    for key in sorted(used-args):
        if key.startswith('unknown_'): continue
        bits=widths.get(key,lifter.bits)
        slot=slots.get(key); kind='stack' if slot else ('temporary' if re.fullmatch(r'(?:v|call_)\d+',key) else 'register')
        storage=('entry SP %s 0x%x'%('+' if slot['offset']>=0 else '-',abs(slot['offset']))) if slot else ('lifted value' if kind=='temporary' else ('incoming machine state' if key in lifter.blocks[0].livein or key=='entry_stack' else 'value across control-flow edges'))
        variables.append(dict(name=key,type='bool' if bits==1 else 'uint%d_t'%bits,kind=kind,storage=storage,addresses=[hex(a) for a in sorted(slot['addresses'])] if slot else []))
    if any(v['storage']=='incoming machine state' and v['name'] not in (lifter.sp,lifter.fp,'entry_stack') for v in variables): lifter.warning('Uninitialized machine-state locals represent values entering this discovered region; the function boundary or prototype may be incomplete.')
    return variables


def symbolize_values(a,blocks):
    symbols={number(s['address']):s['name'] for s in a.get('symbols',[]) if number(s['address']) and s['kind'] not in ('import','import pointer','stub')}
    strings={number(s['address']):s['value'] for s in a.get('strings',[]) if s['address'] and s['encoding']=='ASCII' and s.get('terminated',False)}
    def visit(e,ptr=False):
        e=replace(e,args=tuple(visit(child,e.op=='load') for child in e.args))
        if ptr and e.op=='const':
            if e.value in strings: return E('string',bits=e.bits,value=strings[e.value]).at(*e.sources())
            if e.value in symbols: return E('addr',bits=e.bits,value=symbols[e.value]).at(*e.sources())
        return e
    pointers={'strlen':{0},'puts':{0},'strcmp':{0,1},'strncmp':{0,1},'printf':{0},'fprintf':{1},'strcpy':{0,1},'strncpy':{0,1},'memcpy':{0,1},'memcmp':{0,1},'memset':{0},'free':{0}}
    for b in blocks:
        for op in b.ops+[b.term]:
            if op.expr: op.expr=visit(op.expr)
            callee=op.expr.value if op.kind=='call' and op.expr.op in ('var','function') else ''
            if op.kind=='call' and op.target is not None:
                function=next((f for f in a.get('functions',[]) if number(f['address'])==op.target),None)
                if function: callee=ident(function.get('semanticName',function['name']))
            op.args=[visit(e,op.kind=='store' or idx in pointers.get(callee,set())) for idx,e in enumerate(op.args)]


def serialize_ir(blocks):
    result=[]
    for b in blocks:
        for op in b.ops+[b.term]:
            result.append(dict(block=hex(b.start),kind=op.kind,destination=op.dst,expression=op.expr.text() if op.expr else '',
                               arguments=[e.text() for e in op.args],target=hex(op.target) if op.target is not None else '',
                               addresses=[hex(a) for a in sorted(op.sources())],detail=op.detail))
    return result


def decompile(a,function_address='',names=None,abi='auto',optimize_values=True):
    if a.get('endian','little')!='little': raise ValueError('Decompiler lifters currently validate little-endian code only; use Disassembly for this file')
    if a['arch'] not in ('arm64','arm64e','aarch64','x86','x86_64'):
        raise ValueError('The original decompiler currently lifts ARM64 and x86/x64 scalar integer code. Other architectures remain available in Disassembly.')
    if not a.get('functions'): raise ValueError('No discovered functions to decompile')
    candidates=[f for f in a['functions'] if f['address']==function_address or f['name']==function_address] if function_address else a['functions'][:1]
    if len(candidates)!=1: raise ValueError('Select one unambiguous function start address')
    function=candidates[0]
    instructions=[i for i in a['instructions'] if i['function']==function['name'] and number(function['address'])<=number(i['address'])<=number(function['end'])]
    if not instructions: raise ValueError('No instructions in selected function')
    if len({i['address'] for i in instructions})!=len(instructions) or len({i['section'] for i in instructions})!=1:
        raise ValueError('Function contains overlapping section addresses; decompile a linked image with unique virtual addresses')
    if len(instructions)>MAX_FUNCTION: raise ValueError('Function exceeds the 3,000-instruction decompiler limit; use Disassembly and Control Flow')
    blocks=cfg(instructions)
    lifter=Lifter(a,blocks,abi).lift()
    if lifter.slots and (lifter.unsupported or lifter.stack_escaped):
        reason='Stack recovery is disabled because a stack address escapes to a call or unsupported effects invalidate stack assumptions.'
        blocks=cfg(instructions); lifter=Lifter(a,blocks,abi,recover_stack=False).lift(); lifter.warning(reason)
    normalize_cdecl_arguments(lifter)
    repair_stack_aliases(lifter)
    analyze_liveness(blocks)
    raw_ir=serialize_ir(blocks)
    if optimize_values:
        for b in blocks: optimize(b)
    symbolize_values(a,blocks)
    display={}
    if names:
        if not isinstance(names,dict) or len(names)>500: raise ValueError('At most 500 variable display names are allowed')
        values=set()
        for key,value in names.items():
            if not isinstance(key,str) or not isinstance(value,str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,79}',value) or ident(value)!=value: raise ValueError('Variable display names must be nonreserved C identifiers (up to 80 characters)')
            if value in values: raise ValueError('Variable display names must be unique')
            display[key]=value; values.add(value)
    variables=recover_variables(lifter,display)
    # Reject collisions with generated/default names as well as explicit edits.
    rendered=[display.get(v['name'],v['name']) for v in variables]
    if len(rendered)!=len(set(rendered)): raise ValueError('Display name collides with another recovered variable')
    callees={op.expr.value for b in blocks for op in b.ops if op.kind=='call' and op.expr.op=='function'}|{ident(function['name'])}
    if set(rendered)&callees: raise ValueError('Variable name collides with a function name in this pseudocode')
    for v in variables:
        v['displayName']=display.get(v['name'],v['name'])
        # Preserve optimized value uses and original storage definitions for the
        # disassembly rename picker, including register-derived temporaries.
        origins=set(v['addresses'])
        for b in blocks:
            for op in b.ops+[b.term]:
                if op.dst==v['name'] or v['name'] in op.refs(): origins.update(hex(n) for n in op.sources())
        v['addresses']=sorted(origins,key=lambda n:int(n,16))
    renderer=Renderer(a,lifter,display)
    lines=renderer.render(function,variables)
    mapped={addr for line in lines for addr in line['addresses']}
    reverse=defaultdict(list)
    for line in lines:
        for addr in line['addresses']: reverse[addr].append(line['id'])
    diagnostics=['Pseudocode models machine-width operations. It is not original source code or a promise of recompilability.',
                 'Function boundaries, argument counts and types are inferred. Loads/stores use explicit width helpers.']+lifter.diagnostics
    if any(i['offset']<0 or not i['bytes'] for i in instructions): diagnostics.append('Some instructions have no proven file bytes; patch navigation is disabled for those instructions.')
    if lifter.unsupported: diagnostics.append('%d instruction(s) have unsupported effects; inspect their asm_effect lines.'%len(lifter.unsupported))
    return dict(version=VERSION,function=function,arch=a['arch'],abi=lifter.abi,sha256=a['sha256'],slice=a.get('selectedSlice',0),
                lines=lines,variables=variables,diagnostics=diagnostics,instructions=instructions,
                blocks=[dict(address=hex(b.start),successors=[hex(s) for s in b.succ],predecessors=[hex(p) for p in sorted(b.pred)],liveIn=sorted(b.livein),liveOut=sorted(b.liveout)) for b in blocks],
                ir=raw_ir,optimizedIR=serialize_ir(blocks),reverseMap=dict(reverse),
                coverage=dict(total=len(instructions),mapped=len(mapped),lifted=len(instructions)-len(lifter.unsupported),unsupported=len(lifter.unsupported),blocks=len(blocks),loops=renderer.structured_loops,conditionals=renderer.structured_ifs),
                text='\n'.join(line['text'] for line in lines)+'\n')


def request(path,function='',slice_index=0,expected_hash='',names=None,abi='auto',function_names=None):
    import analysis
    a=analysis.analyze(path,slice_index,function_names=function_names)
    if expected_hash and a['sha256']!=expected_hash: raise ValueError('Binary changed since analysis; reopen it before decompiling')
    return decompile(a,function,names,abi)
