"""Equal-size instruction rewrites verified by LLVM decode; not a linker or reassembler.
preview() never touches the source file; patch() exports the final copy."""
import re
import struct
import tempfile
import analysis
from decompiler import operands, number


def rewrite(arch,ins,kind,value=''):
    raw=bytes.fromhex(ins['bytes']); addr=int(ins['address'],16)
    if not raw: raise ValueError('Instruction has no proven file bytes')
    if arch in ('arm64','arm64e','aarch64'):
        if len(raw)!=4: raise ValueError('ARM64 instruction must be exactly four bytes')
        word=int.from_bytes(raw,'little'); conditional=False; delta=None
        if word & 0xff000010 == 0x54000000:
            conditional=True; immediate=(word>>5)&0x7ffff; delta=(immediate-(1<<19) if immediate&(1<<18) else immediate)*4; invert=word^1
        elif word & 0x7e000000 == 0x34000000:
            conditional=True; immediate=(word>>5)&0x7ffff; delta=(immediate-(1<<19) if immediate&(1<<18) else immediate)*4; invert=word^(1<<24)
        elif word & 0x7e000000 == 0x36000000:
            conditional=True; immediate=(word>>5)&0x3fff; delta=(immediate-(1<<14) if immediate&(1<<13) else immediate)*4; invert=word^(1<<24)
        if kind=='nop': new=0xd503201f
        elif kind=='invert' and conditional: new=invert
        elif kind=='always' and conditional: new=0x14000000|((delta//4)&0x3ffffff)
        elif kind=='immediate':
            n=number(value)
            if n is None: raise ValueError('Enter an integer immediate (decimal or 0x hex)')
            if word & 0x1f800000 == 0x12800000: # MOVN/MOVZ/MOVK immediate field
                if not 0<=n<=0xffff: raise ValueError('MOV-wide field must be 0…65535; existing shift and opcode are preserved')
                new=(word&~(0xffff<<5))|(n<<5)
            elif word & 0x1f000000 == 0x11000000: # ADD/SUB immediate, including CMP aliases
                if not 0<=n<=0xfff: raise ValueError('ADD/SUB field must be 0…4095; existing shift is preserved')
                new=(word&~(0xfff<<10))|(n<<10)
            else: raise ValueError('Immediate editing supports ARM64 MOV-wide and ADD/SUB immediate encodings')
        else: raise ValueError('This rewrite requires a conditional branch')
        return new.to_bytes(4,'little')
    if arch not in ('x86','x86_64'): raise ValueError('Instruction rewrites currently support ARM64 and x86/x64')
    if kind=='nop': return b'\x90'*len(raw)
    short=len(raw)==2 and 0x70<=raw[0]<=0x7f
    near=len(raw)==6 and raw[0]==0x0f and 0x80<=raw[1]<=0x8f
    if kind=='invert':
        if short: return bytes([raw[0]^1])+raw[1:]
        if near: return raw[:1]+bytes([raw[1]^1])+raw[2:]
        raise ValueError('Invert supports unprefixed x86 Jcc rel8/rel32 encodings')
    if kind=='always':
        if short: return b'\xeb'+raw[1:]
        if near:
            delta=int.from_bytes(raw[2:],'little',signed=True)+1
            if not -(1<<31)<=delta<(1<<31): raise ValueError('Replacement displacement does not fit')
            return b'\xe9'+delta.to_bytes(4,'little',signed=True)+b'\x90'
        raise ValueError('Always-branch supports unprefixed x86 Jcc rel8/rel32 encodings')
    if kind=='immediate':
        n=number(value)
        if n is None: raise ValueError('Enter an integer immediate (decimal or 0x hex)')
        p=operands(ins['operands'])
        if len(p)<2 or number(p[-1]) is None: raise ValueError('Instruction has no supported trailing integer immediate')
        prefix=1 if arch=='x86_64' and 0x40<=raw[0]<=0x4f else 0
        op=raw[prefix]; count=None; signed=False
        if 0xb8<=op<=0xbf: count=8 if prefix and raw[0]&8 else 4
        elif 0xb0<=op<=0xb7: count=1
        elif op in (0x83,0x6b): count=1; signed=True
        elif op in (0x81,0xc7,0x69,0x05,0x0d,0x15,0x1d,0x25,0x2d,0x35,0x3d): count=4; signed=arch=='x86_64' and prefix and bool(raw[0]&8)
        if count is None or len(raw)<=count+prefix: raise ValueError('This immediate encoding is not supported; use explicit hex bytes')
        low=-(1<<(count*8-1)); high=(1<<(count*8-(1 if signed else 0)))-1
        if not low<=n<=high: raise ValueError('Immediate does not fit the existing %d-bit field%s'%(count*8,' (sign extended)' if signed else ''))
        return raw[:-count]+(n&((1<<(count*8))-1)).to_bytes(count,'little')
    raise ValueError('Unknown rewrite operation')


def preview(path,address,kind,value='',slice_index=0,expected_hash='',section='',analyzed=None):
    a=analyzed if analyzed is not None else analysis.analyze(path,slice_index)
    if a['endian']!='little': raise ValueError('Instruction rewrite encoders support little-endian targets only')
    if not expected_hash or a['sha256']!=expected_hash: raise ValueError('Source hash is missing or stale; reopen the binary before preparing a patch')
    candidates=[i for i in a['instructions'] if i['address']==address and (not section or i['section']==section)]
    if len(candidates)!=1: raise ValueError('Instruction address is ambiguous; select an exact section and instruction')
    ins=candidates[0]; offset=ins['offset']
    if offset<0: raise ValueError('Instruction is not mapped to file bytes')
    replacement=rewrite(a['arch'],ins,kind,value)
    original=bytes.fromhex(ins['bytes'])
    if len(original)!=len(replacement): raise ValueError('Rewrite changed the instruction span size')
    _,data=analysis.load_file(path)
    import hashlib
    if hashlib.sha256(data).hexdigest()!=expected_hash: raise ValueError('Source changed while preparing the patch')
    if data[offset:offset+len(original)]!=original: raise ValueError('Decoded bytes do not match the source')
    patched=data[:offset]+replacement+data[offset+len(original):]
    with tempfile.NamedTemporaryFile(prefix='asteria-preview-') as f:
        f.write(patched); f.flush(); verified=analysis.analyze(f.name,slice_index,recognize=False)
    after=[i for i in verified['instructions'] if offset<=i['offset']<offset+len(original) and i['section']==ins['section']]
    if sum(len(bytes.fromhex(i['bytes'])) for i in after)!=len(replacement) or any(i['mnemonic'] in ('unknown','.byte') for i in after):
        raise ValueError('LLVM could not verify exact replacement instruction boundaries')
    return dict(address=address,offset=offset,size=len(original),before=ins['bytes'],after=replacement.hex(' '),
                original=ins['mnemonic']+' '+ins['operands'],replacement='\n'.join(i['address']+'  '+i['mnemonic']+' '+i['operands'] for i in after),
                sha256=a['sha256'],kind=kind,warning='Equal-length instruction rewrite. Export a new copy, then reanalyze it. Signatures/checksums may become invalid.')
