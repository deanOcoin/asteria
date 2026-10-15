"""Bounded binary inspection. No sample execution; Python standard library only."""
import collections
import hashlib
import json
import math
import os
import re
import struct
import subprocess
import tempfile
from pathlib import Path

MAX_FILE = 256 * 1024 * 1024
MAX_TABLE = 200000
MAX_STRINGS = 30000
MAX_INSTRUCTIONS = 120000
MAX_TOOL = 32 * 1024 * 1024

class FormatError(ValueError):
    pass

class Reader:
    def __init__(self, data, endian='<'):
        self.data, self.endian = data, endian
    def read(self, off, size):
        if off < 0 or size < 0 or off > len(self.data) - size:
            raise FormatError('Truncated structure at file offset 0x%x (%d bytes requested)' % (off, size))
        return self.data[off:off + size]
    def unpack(self, fmt, off):
        return struct.unpack(self.endian + fmt, self.read(off, struct.calcsize(self.endian + fmt)))
    def n(self, fmt, off):
        return self.unpack(fmt, off)[0]
    def cstr(self, off, limit=4096):
        if off < 0 or off >= len(self.data):
            raise FormatError('String offset outside file: 0x%x' % off)
        return self.data[off:off + limit].split(b'\0', 1)[0].decode('utf-8', 'replace')
    def table(self, off, count, stride):
        if count < 0 or count > MAX_TABLE or stride <= 0:
            raise FormatError('Invalid or excessive table size')
        self.read(off, count * stride)
        return range(count)

def hx(value):
    return '0x%x' % value

def entropy(data):
    if not data:
        return 0.0
    size = len(data)
    return round(-sum((n / size) * math.log2(n / size) for n in collections.Counter(data).values()), 3)

def load_file(path):
    p = Path(path).expanduser().resolve()
    if not p.is_file():
        raise ValueError('Choose a regular binary file')
    if p.stat().st_size > MAX_FILE:
        raise ValueError('This release supports files up to 256 MiB')
    with p.open('rb') as f:
        data = f.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        raise ValueError('File exceeded 256 MiB during read')
    return p, data

def base_report():
    return dict(format='Raw', arch='unknown', bits=0, endian='little', entry='0x0', imageBase='0x0',
                sections=[], symbols=[], imports=[], exports=[], libraries=[], headers=[], slices=[], warnings=[], regions=[], members=[])

def field(a, key, value):
    a['headers'].append(dict(name=key, value=str(value)))

def section(a, name, address, offset, size, virtual_size, flags, data, zero=False):
    if size and not zero and (offset < 0 or offset > len(data) - size):
        raise FormatError('Section %s extends past end of file' % name)
    a['sections'].append(dict(name=name, address=hx(address), offset=offset, size=0 if zero else size,
                             virtualSize=virtual_size, flags=flags, entropy=entropy(data[offset:offset + size]) if not zero else 0.0))

def va_offset(a, address):
    # Never map virtual-only tails (BSS) to unrelated on-disk bytes.
    for s in a['sections']:
        delta = address - int(s['address'], 16)
        if 0 <= delta < s['size']:
            return s['offset'] + delta
    for s in a['regions']:
        delta = address - int(s['address'], 16)
        if 0 <= delta < s['size']:
            return s['offset'] + delta
    return None

def offset_va(a, off):
    for s in a['sections'] + a['regions']:
        if s['offset'] <= off < s['offset'] + s['size']:
            return int(s['address'], 16) + off - s['offset']
    return None

def symbol(a, name, address, kind, library='', size=0):
    s = dict(name=name, address=hx(address), kind=kind, library=library, size=size)
    a['symbols'].append(s)
    if kind == 'import':
        a['imports'].append(s)
    elif kind == 'export':
        a['exports'].append(s)

MACH_ARCH = {7:'x86', 0x1000007:'x86_64', 12:'arm', 0x100000c:'arm64', 0x200000c:'arm64_32'}
MACH_MAGIC = {b'\xce\xfa\xed\xfe':('<',32), b'\xcf\xfa\xed\xfe':('<',64), b'\xfe\xed\xfa\xce':('>',32), b'\xfe\xed\xfa\xcf':('>',64)}

def parse_macho(data, a, base=0):
    order, bits = MACH_MAGIC[data[:4]]
    r = Reader(data, order)
    cpu, subtype, filetype, ncmd, cmdsize, flags = r.unpack('IIIIII', 4)
    a.update(format='Mach-O', arch=MACH_ARCH.get(cpu, hx(cpu)), bits=bits, endian='little' if order == '<' else 'big')
    pos, symtab, mainoff = (32 if bits == 64 else 28), None, None
    indirect = None; indirect_sections = []; indexed_symbols = {}
    if ncmd > MAX_TABLE:
        raise FormatError('Excessive Mach-O load command count')
    end = pos + cmdsize
    r.read(pos, cmdsize)
    for key, val in [('File type', {1:'Object',2:'Executable',6:'Dynamic library',8:'Bundle',4:'Core'}.get(filetype, filetype)), ('Flags', hx(flags)), ('PIE', bool(flags & 0x200000)), ('CPU subtype', hx(subtype)), ('Load commands', ncmd)]:
        field(a, key, val)
    for _ in range(ncmd):
        cmd, size = r.unpack('II', pos)
        if size < 8 or pos + size > end:
            raise FormatError('Invalid Mach-O load command size')
        r.read(pos, size)
        if cmd in (1, 0x19):
            is64 = cmd == 0x19
            minimum = 72 if is64 else 56
            if size < minimum:
                raise FormatError('Truncated segment command')
            segname = r.read(pos+8,16).split(b'\0')[0].decode('utf-8','replace')
            vmaddr, vmsize, foff, fsize = r.unpack('QQQQ' if is64 else 'IIII', pos+24)
            maxprot, initprot, nsect, sflags = r.unpack('IIII', pos+(56 if is64 else 40))
            if fsize: r.read(foff, fsize)
            perms = ''.join(c if initprot & v else '-' for c,v in [('r',1),('w',2),('x',4)])
            a['regions'].append(dict(name=segname, address=hx(vmaddr), offset=foff+base, size=fsize, virtualSize=vmsize, flags=perms, entropy=0.0))
            if segname == '__TEXT': a['imageBase'] = hx(vmaddr)
            stride = 80 if is64 else 68
            if nsect > MAX_TABLE or minimum + nsect * stride > size:
                raise FormatError('Invalid Mach-O section count')
            for j in range(nsect):
                p = pos + minimum + j * stride
                name = r.read(p,16).split(b'\0')[0].decode('utf-8','replace')
                addr, sz = r.unpack('QQ' if is64 else 'II', p+32)
                off, align, reloff, nreloc, sf = r.unpack('IIIII', p+(48 if is64 else 40))
                zero = (sf & 0xff) in (1, 12, 18)
                section(a, segname+','+name, addr, off, sz, sz, perms, data, zero)
                a['sections'][-1]['offset'] += base
                if sf & 0xff in (6,7,8):
                    first, stubsize = r.unpack('II',p+(68 if is64 else 60))
                    stride_indirect = stubsize if sf & 0xff == 8 else bits//8
                    if stride_indirect: indirect_sections.append((addr,sz,stride_indirect,first,sf & 0xff))
        elif cmd == 0xb:
            if size < 80: raise FormatError('Truncated dynamic symbol command')
            indirect = r.unpack('II',pos+56)
        elif cmd == 2:
            if size < 24: raise FormatError('Truncated symbol command')
            symtab = r.unpack('IIII', pos+8)
        elif cmd in (0xc, 0x18|0x80000000, 0x1f|0x80000000, 0x20, 0x23|0x80000000, 0xd):
            if size < 24: raise FormatError('Truncated dylib command')
            noff = r.n('I',pos+8)
            if not 24 <= noff < size: raise FormatError('Invalid dylib name offset')
            name = r.cstr(pos+noff, size-noff)
            if cmd != 0xd: a['libraries'].append(name)
            else: field(a, 'Library ID', name)
        elif cmd == 0x80000028:
            if size < 24: raise FormatError('Truncated entry command')
            mainoff = r.n('Q', pos+8)
        elif cmd == 0x1b:
            field(a, 'UUID', r.read(pos+8, 16).hex())
        elif cmd == 0x1d:
            field(a, 'Code signature', 'Present (not cryptographically verified)')
        elif cmd in (0x21, 0x2c):
            if size >= 20: field(a, 'Encrypted', bool(r.n('I',pos+16)))
        pos += size
    if mainoff is not None:
        for s in a['regions']:
            if s['name'] == '__TEXT': a['entry'] = hx(int(s['address'],16) + mainoff)
    if symtab:
        off, count, stroff, strsize = symtab
        r.read(stroff, strsize)
        for j in r.table(off,count,16 if bits==64 else 12):
            p = off+j*(16 if bits==64 else 12)
            si, typ, sect, desc = r.unpack('IBBH',p)
            value = r.n('Q' if bits==64 else 'I',p+8)
            if not si or si >= strsize or typ & 0xe0: continue
            name = r.cstr(stroff+si,strsize-si)
            kind = 'import' if typ & 0x0e == 0 else ('export' if typ & 1 else 'symbol')
            ordinal = (desc >> 8) & 0xff
            lib = a['libraries'][ordinal-1] if kind=='import' and 0 < ordinal <= len(a['libraries']) else ''
            symbol(a,name,value,kind,lib)
            indexed_symbols[j]=(name,lib)
    if indirect and indexed_symbols:
        indirectoff, indirectcount=indirect
        r.table(indirectoff,indirectcount,4)
        for addr,sz,stride,first,typ in indirect_sections:
            count=sz//stride
            if first>indirectcount or count>indirectcount-first: raise FormatError('Indirect symbol section exceeds table')
            for j in range(count):
                index=r.n('I',indirectoff+(first+j)*4)
                if index & 0xc0000000: continue
                if index in indexed_symbols:
                    name,lib=indexed_symbols[index]
                    symbol(a,name,addr+j*stride,'stub' if typ==8 else 'import pointer',lib,stride)

PE_ARCH = {0x14c:'x86',0x8664:'x86_64',0x1c0:'arm',0x1c4:'thumb',0xaa64:'arm64'}

def parse_pe(data, a, coff=False):
    r = Reader(data)
    pe = 0 if coff else r.n('I',0x3c)
    if not coff and r.read(pe,4) != b'PE\0\0': raise FormatError('Missing PE signature')
    p = pe if coff else pe+4
    machine, count, stamp, symoff, nsyms, optsize, flags = r.unpack('HHIIIHH',p)
    a.update(format='COFF' if coff else 'PE', arch=PE_ARCH.get(machine,hx(machine)), bits=64 if machine in (0x8664,0xaa64) else 32)
    field(a,'Machine',hx(machine)); field(a,'Characteristics',hx(flags)); field(a,'Timestamp',stamp)
    opt, imagebase, dirs = p+20, 0, []
    if not coff:
        r.read(opt,optsize)
        magic = r.n('H',opt)
        if magic not in (0x10b,0x20b): raise FormatError('Unsupported PE optional header')
        bits = 64 if magic==0x20b else 32
        minimum = 112 if bits==64 else 96
        if optsize < minimum: raise FormatError('Truncated PE optional header')
        a['bits'] = bits
        imagebase = r.n('Q',opt+24) if bits==64 else r.n('I',opt+28)
        a['imageBase'] = hx(imagebase)
        entryrva = r.n('I',opt+16)
        a['entry'] = hx(imagebase+entryrva) if entryrva else '0x0'
        dllflags = r.n('H',opt+70)
        field(a,'Subsystem',r.n('H',opt+68)); field(a,'ASLR',bool(dllflags&0x40)); field(a,'NX compatible',bool(dllflags&0x100)); field(a,'Control Flow Guard',bool(dllflags&0x4000))
        ndirs = r.n('I', opt+minimum-4)
        if ndirs > (optsize-minimum)//8: raise FormatError('PE data directories exceed optional header')
        dirs = [r.unpack('II',opt+minimum+i*8) for i in range(min(ndirs,16))]
        headersize = min(r.n('I',opt+60),len(data))
        a['regions'].append(dict(name='PE headers',address=hx(imagebase),offset=0,size=headersize,virtualSize=headersize,flags='r--',entropy=0.0))
        for i, (address, size) in enumerate(dirs):
            if size: field(a, ['Exports','Imports','Resources','Exceptions','Certificate','Relocations','Debug','Architecture','Global pointer','TLS','Load configuration','Bound import','IAT','Delay import','CLR','Reserved'][i], '%s / %d bytes' % (hx(address),size))
    table = opt+optsize
    if count > 4096: raise FormatError('Excessive COFF section count')
    for i in r.table(table,count,40):
        q = table+i*40
        name = r.read(q,8).split(b'\0')[0].decode('utf-8','replace')
        vs, va, size, off = r.unpack('IIII',q+8)
        sf = r.n('I',q+36)
        perms = ''.join(c if sf&v else '-' for c,v in [('r',0x40000000),('w',0x80000000),('x',0x20000000)])
        section(a,name,imagebase+va,off,size,vs or size,perms,data,zero=not off and bool(sf&0x80))
    def rva(v, length=1):
        off=va_offset(a,imagebase+v)
        if off is None: raise FormatError('Unmapped PE RVA '+hx(v))
        r.read(off,length)
        return off
    if not coff and len(dirs)>1 and dirs[1][0]:
        start, sz=dirs[1]
        for i in range(min(sz//20,16384)):
            q=rva(start+i*20,20)
            orig,stamp,chain,name,thunk=r.unpack('IIIII',q)
            if not any((orig,stamp,chain,name,thunk)): break
            lib=r.cstr(rva(name)); a['libraries'].append(lib)
            width=8 if a['bits']==64 else 4
            for j in range(65536):
                value=r.n('Q' if width==8 else 'I',rva((orig or thunk)+j*width,width))
                if not value: break
                name='#%d'%(value&0xffff) if value&(1<<(width*8-1)) else r.cstr(rva(value)+2)
                symbol(a,name,imagebase+thunk+j*width,'import',lib)
    if not coff and dirs and dirs[0][0]:
        q=rva(dirs[0][0],40)
        ordinal,nfun,nnames,fun,names,ords=r.unpack('IIIIII',q+16)
        if max(nfun,nnames)>MAX_TABLE: raise FormatError('Excessive PE export count')
        named={}
        for i in range(nnames):
            index=r.n('H',rva(ords+i*2,2))
            if index>=nfun: raise FormatError('Invalid PE export ordinal')
            named[index]=r.cstr(rva(r.n('I',rva(names+i*4,4))))
        for i in range(nfun):
            v=r.n('I',rva(fun+i*4,4))
            if v:
                forwarded = r.cstr(rva(v)) if dirs[0][0]<=v<dirs[0][0]+dirs[0][1] else ''
                symbol(a,named.get(i,'#%d'%(ordinal+i)),imagebase+v,'export',forwarded)
    if symoff and nsyms:
        r.table(symoff,nsyms,18)
        so=symoff+nsyms*18
        slen=r.n('I',so)
        r.read(so,slen)
        j=0
        while j<nsyms:
            q=symoff+j*18
            raw=r.read(q,8)
            index=r.n('I',q+4)
            name=r.cstr(so+index,slen-index) if raw[:4]==b'\0'*4 and 4<=index<slen else raw.split(b'\0')[0].decode('utf-8','replace')
            value,sect,typ,storage,aux=r.unpack('IhHBB',q+8)
            addr=(int(a['sections'][sect-1]['address'],16)+value) if 0<sect<=len(a['sections']) else value
            if name: symbol(a,name,addr,'import' if sect==0 else 'symbol')
            if j+aux>=nsyms: raise FormatError('Invalid COFF auxiliary symbol count')
            j+=1+aux

ELF_ARCH = {3:'x86',62:'x86_64',40:'arm',183:'arm64',243:'riscv',8:'mips',20:'ppc',21:'ppc64'}

def parse_elf(data,a):
    if len(data)<16 or data[4] not in (1,2) or data[5] not in (1,2): raise FormatError('Invalid ELF identification')
    bits=64 if data[4]==2 else 32
    r=Reader(data,'<' if data[5]==1 else '>')
    fmt='HHIQQQIHHHHHH' if bits==64 else 'HHIIIIIHHHHHH'
    typ,machine,version,entry,phoff,shoff,flags,ehsize,phents,phnum,shents,shnum,shstr=r.unpack(fmt,16)
    a.update(format='ELF',arch=ELF_ARCH.get(machine,hx(machine)),bits=bits,endian='little' if data[5]==1 else 'big',entry=hx(entry))
    field(a,'Object type',{1:'Relocatable',2:'Executable',3:'Shared / PIE',4:'Core'}.get(typ,typ)); field(a,'OS ABI',data[7]); field(a,'Flags',hx(flags))
    sfmt='IIQQQQIIQQ' if bits==64 else 'IIIIIIIIII'
    smin=64 if bits==64 else 40
    if shoff and shents<smin: raise FormatError('ELF section stride too small')
    if shoff and (shnum==0 or shstr==0xffff or phnum==0xffff):
        zero=r.unpack(sfmt,shoff)
        if shnum==0: shnum=zero[5]
        if shstr==0xffff: shstr=zero[6]
        if phnum==0xffff: phnum=zero[7]
    sections=[r.unpack(sfmt,shoff+i*shents) for i in r.table(shoff,shnum,shents)] if shoff else []
    if shstr>=len(sections) and shstr!=0: raise FormatError('Invalid ELF section name table')
    namebytes=r.read(sections[shstr][4],sections[shstr][5]) if sections and shstr else b''
    def string_at(blob,index):
        return blob[index:].split(b'\0',1)[0].decode('utf-8','replace') if 0<=index<len(blob) else ''
    for i,s in enumerate(sections):
        no,st,fl,addr,off,size,link,info,align,ents=s
        name=string_at(namebytes,no) or ('section_%d'%i)
        perms=('r' if fl&2 else '-')+('w' if fl&1 else '-')+('x' if fl&4 else '-')
        section(a,name,addr,off,size,size,perms,data,zero=st in (0,8))
    if phnum and phents<(56 if bits==64 else 32): raise FormatError('ELF program stride too small')
    for i in r.table(phoff,phnum,phents) if phnum else []:
        q=phoff+i*phents
        if bits==64: pt,pf,off,va,pa,fs,vs,align=r.unpack('IIQQQQQQ',q)
        else: pt,off,va,pa,fs,vs,pf,align=r.unpack('IIIIIIII',q)
        if fs: r.read(off,fs)
        if pt==1:
            a['regions'].append(dict(name='LOAD',address=hx(va),offset=off,size=fs,virtualSize=vs,flags=''.join(c if pf&v else '-' for c,v in [('r',4),('w',2),('x',1)]),entropy=0.0))
        elif pt==3: field(a,'Interpreter',r.cstr(off,fs))
        elif pt==0x6474e551: field(a,'Executable stack',bool(pf&1))
        elif pt==0x6474e552: field(a,'RELRO segment','Present')
    if a['regions']: a['imageBase']=hx(min(int(s['address'],16) for s in a['regions']))
    for s in sections:
        no,st,fl,addr,off,size,link,info,align,ents=s
        if st in (2,11):
            if link>=len(sections): raise FormatError('Invalid ELF symbol string table')
            ls=sections[link]; strings=r.read(ls[4],ls[5])
            minimum=24 if bits==64 else 16
            if ents<minimum or size%ents: raise FormatError('Invalid ELF symbol stride')
            for j in r.table(off,size//ents,ents):
                p=off+j*ents
                if bits==64: ni,si,other,shndx,value,sz=r.unpack('IBBHQQ',p)
                else: ni,value,sz,si,other,shndx=r.unpack('IIIBBH',p)
                name=string_at(strings,ni)
                if not name: continue
                kind='import' if shndx==0 else ('export' if st==11 and si>>4 in (1,2) else ('function' if si&15==2 else 'symbol'))
                symbol(a,name,value,kind,size=sz)
        elif st==6 and link<len(sections):
            ls=sections[link]; strings=r.read(ls[4],ls[5])
            stride=16 if bits==64 else 8
            for j in r.table(off,size//stride,stride):
                tag,val=r.unpack('qQ' if bits==64 else 'iI',off+j*stride)
                if tag==0: break
                if tag==1: a['libraries'].append(string_at(strings,val))
                if tag in (15,29): field(a,'RPATH' if tag==15 else 'RUNPATH',string_at(strings,val))

def parse_archive(data,a):
    a['format']='Archive'
    r=Reader(data); off=8; longnames=b''
    while off<len(data):
        h=r.read(off,60)
        if h[58:]!=b'`\n': raise FormatError('Invalid archive member header')
        try: sz=int(h[48:58].strip())
        except ValueError: raise FormatError('Invalid archive member size')
        payload=off+60; r.read(payload,sz)
        name=h[:16].decode('utf-8','replace').strip()
        actual=sz
        if name=='//': longnames=data[payload:payload+sz]
        elif name.startswith('#1/'):
            n=int(name[3:])
            if n>sz: raise FormatError('Invalid archive long name')
            name=r.read(payload,n).rstrip(b'\0').decode('utf-8','replace'); payload+=n; actual-=n
        elif name.startswith('/') and name[1:].isdigit():
            i=int(name[1:]); name=longnames[i:].split(b'/\n',1)[0].decode('utf-8','replace')
        else: name=name.rstrip('/')
        a['members'].append(dict(name=name or '(symbol index)',offset=payload,size=actual))
        if len(a['members'])>MAX_TABLE: raise FormatError('Too many archive members')
        off+=60+sz+(sz%2)
    a['warnings'].append('Archive member listing is available. Extract a member to analyze its code.')

def parse(data,slice_index=0):
    a=base_report(); selected=data
    fat={b'\xca\xfe\xba\xbe':('>',False), b'\xbe\xba\xfe\xca':('<',False), b'\xca\xfe\xba\xbf':('>',True), b'\xbf\xba\xfe\xca':('<',True)}
    if data[:4] in fat:
        order,is64=fat[data[:4]]; r=Reader(data,order); n=r.n('I',4)
        if n>64 or n==0: raise FormatError('Invalid universal slice count')
        stride=32 if is64 else 20
        for i in r.table(8,n,stride):
            q=8+i*stride
            if is64: cpu,sub,off,sz,align,reserved=r.unpack('IIQQII',q)
            else: cpu,sub,off,sz,align=r.unpack('IIIII',q)
            r.read(off,sz)
            a['slices'].append(dict(index=i,arch=MACH_ARCH.get(cpu,hx(cpu)),offset=off,size=sz))
        if not 0<=slice_index<n: raise ValueError('Slice index out of range')
        s=a['slices'][slice_index]; selected=data[s['offset']:s['offset']+s['size']]
        if selected[:4] not in MACH_MAGIC: raise FormatError('Universal slice is not Mach-O')
        parse_macho(selected,a,s['offset']); a['format']='Mach-O Universal'
    elif data[:4] in MACH_MAGIC: parse_macho(data,a)
    elif data[:4]==b'\x7fELF': parse_elf(data,a)
    elif data[:2]==b'MZ': parse_pe(data,a)
    elif data[:8]==b'!<arch>\n': parse_archive(data,a)
    elif len(data)>=20 and int.from_bytes(data[:2],'little') in PE_ARCH: parse_pe(data,a,True)
    else:
        section(a,'raw',0,0,len(data),len(data),'r--',data)
        a['warnings'].append('Unrecognized format: raw bytes and strings only; no CPU was assumed.')
    return a,selected

def extract_strings(data,a):
    strings=[]
    patterns=[('ASCII',re.compile(rb'[\x20-\x7e]{4,}')),('UTF-16LE',re.compile(rb'(?:[\x20-\x7e]\x00){4,}')),('UTF-16BE',re.compile(rb'(?:\x00[\x20-\x7e]){4,}'))]
    for enc,pattern in patterns:
        for m in pattern.finditer(data):
            value=m.group()[:4096].decode('ascii' if enc=='ASCII' else enc.lower(),'replace')
            address=offset_va(a,m.start())
            strings.append(dict(offset=m.start(),address=hx(address) if address is not None else '',encoding=enc,value=value,terminated=(len(m.group())<=4096 and data[m.end():m.end()+(1 if enc=='ASCII' else 2)]==(b'\0' if enc=='ASCII' else b'\0\0'))))
            if len(strings)>=MAX_STRINGS:
                a['warnings'].append('String limit reached: 30,000 results.'); return sorted(strings,key=lambda x:x['offset'])
    return sorted(strings,key=lambda x:x['offset'])

def llvm_tool(name,args,timeout=40):
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        p=subprocess.Popen(['/usr/bin/xcrun',name]+args,stdout=out,stderr=err)
        try:
            import time
            start=time.monotonic()
            while p.poll() is None:
                if time.monotonic()-start>timeout or out.tell()>MAX_TOOL or err.tell()>MAX_TOOL:
                    p.kill(); p.wait(); raise ValueError('LLVM analysis exceeded time/output limit')
                time.sleep(.03)
            out.seek(0); err.seek(0)
            text=out.read(MAX_TOOL+1); errors=err.read(MAX_TOOL)
            if len(text)>MAX_TOOL: raise ValueError('LLVM output exceeded 32 MiB')
            if p.returncode: raise ValueError(errors.decode('utf-8','replace').strip() or 'LLVM could not inspect this file')
            return text.decode('utf-8','replace')
        finally:
            if p.poll() is None: p.kill(); p.wait()

def branch_kind(m):
    if m in ('bl','blx','blr','blraa','blrab') or m.startswith('call'): return 'call'
    if m in ('ret','retq','retaa','retab','eret'): return 'return'
    if m in ('jmp','jmpq','b','br','braa','brab','bx'): return 'jump'
    if m.startswith('j') or m.startswith('b.') or m in ('cbz','cbnz','tbz','tbnz','beq','bne','bgt','blt','bge','ble','bhi','blo','bhs','bls'): return 'branch'
    return 'instruction'

def disassemble(path,a,selected):
    a.update(instructions=[],functions=[],xrefs=[])
    if a['format'] in ('Raw','Archive'): return
    with tempfile.NamedTemporaryFile(suffix='.bin') as f:
        f.write(selected); f.flush()
        args=['--disassemble','--demangle']
        if a['arch'] in ('x86','x86_64'): args+=['--x86-asm-syntax=intel']
        try: output=llvm_tool('llvm-objdump',args+[f.name])
        except (ValueError,OSError) as e:
            a['warnings'].append(str(e)); return
    labels={}; function=''; current_section=''; section_matches=[]
    section_addresses={id(s):int(s['address'],16) for s in a['sections']}
    for line in output.splitlines():
        if line.startswith('Disassembly of section '):
            current_section=line[23:].rstrip(':')
            section_matches=[s for s in a['sections'] if s['name']==current_section or s['name']==current_section.split(',')[-1] or s['name'].replace('.',',',1)==current_section]
        label=re.match(r'^([0-9a-fA-F]+) <(.*)>:$',line.strip())
        if label:
            address=int(label[1],16); function=label[2]; labels[address]=function; continue
        match=re.match(r'^\s*([0-9a-fA-F]+):\s+((?:(?:[0-9a-fA-F]{2}|[0-9a-fA-F]{8})[ \t]+)+)([A-Za-z.][\w.]*)\s*(.*)$',line)
        if not match: continue
        address=int(match[1],16); decoded_size=len(''.join(match[2].split()))//2; mnemonic=match[3]; operands=match[4].strip(); kind=branch_kind(mnemonic)
        target=None
        # Only an explicit direct branch operand is a code xref, never a memory displacement.
        if kind in ('call','jump','branch'):
            direct=re.search(r'(?:^|[\s,])(?:#)?(0x[0-9a-fA-F]+)',operands.split('<')[0])
            if direct and not any(c in operands.split('<')[0] for c in ('[',']','*','(')):
                target=int(direct[1],16)
                a['xrefs'].append(dict(source=hx(address),target=hx(target),kind=kind,function=function))
        # LLVM section identity disambiguates overlapping relocatable addresses.
        mapped=[s for s in section_matches if 0<=address-section_addresses[id(s)]<s['size']]
        off=(mapped[0]['offset']+address-section_addresses[id(mapped[0])]) if len(mapped)==1 else (va_offset(a,address) if not section_matches else None)
        a['instructions'].append(dict(address=hx(address),offset=off if off is not None else -1,mnemonic=mnemonic,operands=operands,function=function,section=current_section,kind=kind,target=hx(target) if target is not None else '',bytes='',_decodedSize=decoded_size))
        if len(a['instructions'])>=MAX_INSTRUCTIONS:
            a['warnings'].append('Disassembly limit reached: 120,000 instructions.'); break
    instructions=a['instructions']; addresses={int(x['address'],16) for x in instructions}
    for x in a['xrefs']:
        addr=int(x['target'],16)
        if x['kind']=='call' and addr in addresses and addr not in labels: labels[addr]='sub_%x'%addr
    for s in a['symbols']:
        addr=int(s['address'],16)
        if addr in addresses and s['kind'] in ('function','export','stub'): labels[addr]=s['name'] if s['kind']=='stub' or labels.get(addr,'').startswith(('ltmp','Ltmp','.L','lBB','LBB','sub_')) else labels.get(addr,s['name'])
    if instructions: labels.setdefault(int(instructions[0]['address'],16),'entry')
    current=''; groups=collections.OrderedDict()
    for i,x in enumerate(instructions):
        addr=int(x['address'],16)
        if addr in labels: current=labels[addr]; groups.setdefault((addr,current),[])
        x['function']=current
        if groups: groups[next(reversed(groups))].append(x)
        if x['offset']>=0:
            n=x['_decodedSize']
            if 0<n<=16:
                delta=a['slices'][a.get('selectedSlice',0)]['offset'] if a['slices'] else 0
                off=x['offset']-delta
                x['bytes']=selected[off:off+n].hex(' ') if 0<=off<=len(selected)-n else ''
        x.pop('_decodedSize',None)
    for (addr,name),items in groups.items():
        a['functions'].append(dict(name=name,address=hx(addr),count=len(items),end=items[-1]['address']))
    if a['format']=='COFF' or (a['format']=='ELF' and any(h['value']=='Relocatable' for h in a['headers'])):
        a['warnings'].append('Relocatable objects can reuse section-relative addresses; cross-section address navigation is ambiguous.')
    a['warnings'].append('Code references are direct branches/calls. Function boundaries and graphs are heuristic; indirect targets are not resolved.')

def analyze(path,slice_index=0,recognize=True,function_names=None):
    p,data=load_file(path); a,selected=parse(data,slice_index)
    a.update(path=str(p),name=p.name,size=len(data),sha256=hashlib.sha256(data).hexdigest(),md5=hashlib.md5(data).hexdigest(),entropy=entropy(data),selectedSlice=slice_index)
    a['strings']=extract_strings(data,a)
    step=max(1,math.ceil(len(data)/128))
    a['entropyBins']=[dict(offset=i,value=entropy(data[i:i+step])) for i in range(0,len(data),step)]
    disassemble(p,a,selected)
    # Deduplicate common ELF static/dynamic symbols.
    for key in ('symbols','imports','exports'):
        seen=set(); a[key]=[s for s in a[key] if not ((s['name'],s['address'],s['kind']) in seen or seen.add((s['name'],s['address'],s['kind'])))]
    import recognition
    if recognize: recognition.recognize(a)
    recognition.apply_names(a,function_names)
    return a

def hex_view(path,offset=0,count=512):
    p,data=load_file(path); offset=max(0,int(offset)); count=max(1,min(int(count),65536))
    if offset>len(data): raise ValueError('Offset past end of file')
    lines=[]
    for i in range(offset,min(offset+count,len(data)),16):
        chunk=data[i:i+16]
        lines.append('%08x  %-47s  |%s|'%(i,chunk.hex(' '),''.join(chr(c) if 32<=c<127 else '.' for c in chunk)))
    return dict(text='\n'.join(lines),offset=offset,total=len(data))

def search(path,query,mode='text'):
    p,data=load_file(path)
    if not query: raise ValueError('Enter a search pattern')
    if mode=='hex':
        tokens=query.split()
        if not tokens or len(tokens)>1024: raise ValueError('Use up to 1,024 hex byte tokens')
        pieces=[]
        for token in tokens:
            if token in ('??','?'): pieces.append(b'.')
            elif re.fullmatch('[0-9a-fA-F]{2}',token): pieces.append(re.escape(bytes([int(token,16)])))
            else: raise ValueError('Hex format: 48 8B ?? FF')
        pattern=re.compile(b'(?=('+b''.join(pieces)+b'))',re.DOTALL)
    else:
        needle=query.encode('utf-16le' if mode=='utf16' else 'utf-8')
        if len(needle)>4096: raise ValueError('Search text exceeds 4,096 bytes')
        pattern=re.compile(b'(?=('+re.escape(needle)+b'))')
    hits=[]; truncated=False
    for m in pattern.finditer(data):
        if len(hits)>=10000: truncated=True; break
        hits.append(dict(offset=m.start(),bytes=data[m.start():m.start()+32].hex(' ')))
    return dict(hits=hits,truncated=truncated)

def compare(path,other):
    p,left=load_file(path); q,right=load_file(other)
    runs=[]; start=None; changed=0
    for i in range(max(len(left),len(right))):
        diff=(left[i] if i<len(left) else None)!=(right[i] if i<len(right) else None)
        if diff:
            changed+=1
            if start is None: start=i
        elif start is not None:
            if len(runs)<10000: runs.append(dict(offset=start,size=i-start,before=left[start:min(i,start+32)].hex(' '),after=right[start:min(i,start+32)].hex(' ')))
            start=None
    if start is not None and len(runs)<10000: runs.append(dict(offset=start,size=max(len(left),len(right))-start,before=left[start:start+32].hex(' '),after=right[start:start+32].hex(' ')))
    return dict(changed=changed,leftSize=len(left),rightSize=len(right),runs=runs,truncated=len(runs)>=10000)

def patch(path,output,offset,hexbytes,expected_hash=''):
    p,data=load_file(path); q=Path(output).expanduser().resolve()
    if p==q or (q.exists() and os.path.samefile(p,q)): raise ValueError('Choose a separate output file; the original is immutable')
    if expected_hash and hashlib.sha256(data).hexdigest()!=expected_hash: raise ValueError('Source changed since analysis; reopen it before patching')
    try: replacement=bytes.fromhex(hexbytes)
    except ValueError: raise ValueError('Patch must contain complete hex bytes')
    if not replacement or offset<0 or offset>len(data)-len(replacement): raise ValueError('Patch range must fit inside the file')
    changed=data[:offset]+replacement+data[offset+len(replacement):]
    # Exclusive create also prevents races and accidental replacement of existing work.
    with q.open('xb') as f: f.write(changed)
    q.chmod(p.stat().st_mode & 0o777)
    return dict(path=str(q),sha256=hashlib.sha256(changed).hexdigest(),count=len(replacement))
