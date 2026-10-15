import hashlib
import os
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'Engine'))
import analysis as e


def pe(bits=64):
    d=bytearray(0x600)
    d[:2]=b'MZ'; struct.pack_into('<I',d,0x3c,0x80); d[0x80:0x84]=b'PE\0\0'
    opts=240 if bits==64 else 224
    struct.pack_into('<HHIIIHH',d,0x84,0x8664 if bits==64 else 0x14c,1,0,0,0,opts,0x22)
    o=0x98; struct.pack_into('<H',d,o,0x20b if bits==64 else 0x10b)
    struct.pack_into('<I',d,o+16,0x1000)
    base=0x140000000 if bits==64 else 0x400000
    struct.pack_into('<Q' if bits==64 else '<I',d,o+(24 if bits==64 else 28),base)
    struct.pack_into('<II',d,o+32,0x1000,0x200); struct.pack_into('<II',d,o+56,0x2000,0x200)
    struct.pack_into('<HH',d,o+68,3,0x140)
    minimum=112 if bits==64 else 96
    struct.pack_into('<I',d,o+minimum-4,16)
    struct.pack_into('<II',d,o+minimum,0x1200,0x70)
    struct.pack_into('<II',d,o+minimum+8,0x1100,40)
    s=o+opts; d[s:s+8]=b'.text\0\0\0'; struct.pack_into('<IIII',d,s+8,0x500,0x1000,0x400,0x200); struct.pack_into('<I',d,s+36,0x60000020)
    d[0x200:0x206]=b'\xb8\x2a\x00\x00\x00\xc3'
    struct.pack_into('<IIIII',d,0x300,0x1140,0,0,0x1180,0x1160)
    struct.pack_into('<Q' if bits==64 else '<I',d,0x340,0x11a0)
    struct.pack_into('<Q' if bits==64 else '<I',d,0x360,0x11a0)
    d[0x380:0x38d]=b'KERNEL32.dll\0'; d[0x3a0:0x3ad]=b'\0\0ExitProcess'
    struct.pack_into('<IIIIII',d,0x410,1,1,1,0x1230,0x1240,0x1250)
    struct.pack_into('<I',d,0x430,0x1000); struct.pack_into('<I',d,0x440,0x1260); struct.pack_into('<H',d,0x450,0)
    d[0x460:0x467]=b'answer\0'
    return bytes(d)


def elf(bits=64,order='<'):
    d=bytearray(0x400); d[:16]=b'\x7fELF'+bytes([2 if bits==64 else 1,1 if order=='<' else 2,1,0])+b'\0'*8
    names=b'\0.text\0.shstrtab\0.bss\0'; d[0x120:0x120+len(names)]=names
    d[0x100:0x106]=b'\xb8\x2a\0\0\0\xc3'
    if bits==64:
        struct.pack_into(order+'HHIQQQIHHHHHH',d,16,2,62,1,0x400100,64,0x200,0,64,56,1,64,4,2)
        struct.pack_into(order+'IIQQQQQQ',d,64,1,5,0,0x400000,0x400000,len(d),len(d)+0x100,0x1000)
        fmt='IIQQQQIIQQ'; stride=64
    else:
        struct.pack_into(order+'HHIIIIIHHHHHH',d,16,2,3,1,0x400100,52,0x200,0,52,32,1,40,4,2)
        struct.pack_into(order+'IIIIIIII',d,52,1,0,0x400000,0x400000,len(d),len(d)+0x100,5,0x1000)
        fmt='IIIIIIIIII'; stride=40
    for i,v in enumerate([(0,0,0,0,0,0,0,0,0,0),(1,1,6,0x400100,0x100,6,0,0,16,0),(7,3,0,0,0x120,len(names),0,0,1,0),(17,8,3,0x400400,0,0x100,0,0,16,0)]):
        struct.pack_into(order+fmt,d,0x200+i*stride,*v)
    return bytes(d)


def macho(bits=64,order='<'):
    d=bytearray(0x250)
    cpu=0x100000c if bits==64 else 12
    hdr=32 if bits==64 else 28
    segsize=152 if bits==64 else 124
    cmds=segsize+24+24
    magic=0xfeedfacf if bits==64 else 0xfeedface
    struct.pack_into(order+'IIIIIII',d,0,magic,cpu,0,2,3,cmds,0x200000)
    p=hdr; struct.pack_into(order+'II16s',d,p,0x19 if bits==64 else 1,segsize,b'__TEXT')
    struct.pack_into(order+('QQQQ' if bits==64 else 'IIII'),d,p+24,0x1000,len(d),0,len(d))
    struct.pack_into(order+'IIII',d,p+(56 if bits==64 else 40),5,5,1,0)
    s=p+(72 if bits==64 else 56); struct.pack_into(order+'16s16s',d,s,b'__text',b'__TEXT')
    struct.pack_into(order+('QQ' if bits==64 else 'II'),d,s+32,0x1200,8)
    struct.pack_into(order+'IIIII',d,s+(48 if bits==64 else 40),0x200,2,0,0,0x80000400)
    q=p+segsize; struct.pack_into(order+'IIIIII',d,q,2,24,0x210,1,0x230,7)
    struct.pack_into(order+'IIQQ',d,q+24,0x80000028,24,0x200,0)
    d[0x200:0x208]=bytes.fromhex('40058052c0035fd6')
    struct.pack_into(order+'IBBH',d,0x210,1,0xf,1,0)
    struct.pack_into(order+('Q' if bits==64 else 'I'),d,0x218,0x1200)
    d[0x230:0x237]=b'\0_main\0'
    return bytes(d)


def fat(data):
    d=bytearray(0x1000+len(data)); struct.pack_into('>II',d,0,0xcafebabe,1); struct.pack_into('>IIIII',d,8,0x100000c,0,0x1000,len(data),12); d[0x1000:]=data
    return bytes(d)

class FormatTests(unittest.TestCase):
    def test_pe_variants_imports_exports(self):
        for bits in (32,64):
            a,_=e.parse(pe(bits)); self.assertEqual(a['bits'],bits); self.assertEqual(a['format'],'PE')
            self.assertEqual(a['imports'][0]['name'],'ExitProcess'); self.assertEqual(a['libraries'],['KERNEL32.dll']); self.assertEqual(a['exports'][0]['name'],'answer')
            base=0x140000000 if bits==64 else 0x400000
            self.assertEqual(e.va_offset(a,base+0x1000),0x200)
            self.assertIsNone(e.va_offset(a,base+0x1400))
    def test_elf_variants_endianness_and_bss(self):
        for bits in (32,64):
            for order in ('<','>'):
                a,_=e.parse(elf(bits,order)); self.assertEqual(a['bits'],bits); self.assertEqual(a['endian'],'little' if order=='<' else 'big')
                self.assertEqual(a['sections'][1]['name'],'.text'); self.assertEqual(e.va_offset(a,0x400100),0x100)
                self.assertEqual(a['sections'][3]['size'],0); self.assertIsNone(e.va_offset(a,0x400400))
    def test_macho_variants(self):
        for bits in (32,64):
            for order in ('<','>'):
                a,_=e.parse(macho(bits,order)); self.assertEqual(a['bits'],bits); self.assertEqual(a['entry'],'0x1200'); self.assertEqual(a['symbols'][0]['name'],'_main'); self.assertEqual(e.va_offset(a,0x1200),0x200)
    def test_fat_absolute_offsets(self):
        a,selected=e.parse(fat(macho())); self.assertEqual(a['format'],'Mach-O Universal'); self.assertEqual(e.va_offset(a,0x1200),0x1200); self.assertEqual(selected,macho()); self.assertEqual(e.offset_va(a,0x1200),0x1200)
        with self.assertRaises(ValueError): e.parse(fat(macho()),1)
    def test_pe_invalid_directories(self):
        d=bytearray(pe()); struct.pack_into('<I',d,0x98+108,99)
        with self.assertRaises(e.FormatError): e.parse(bytes(d))
    def test_bad_symbol_index(self):
        d=bytearray(pe()); struct.pack_into('<H',d,0x450,4)
        with self.assertRaises(e.FormatError): e.parse(bytes(d))
    def test_bad_elf_section_stride(self):
        d=bytearray(elf()); struct.pack_into('<H',d,58,1)
        with self.assertRaises(e.FormatError): e.parse(bytes(d))
    def test_bad_mach_command(self):
        d=bytearray(macho()); struct.pack_into('<I',d,36,0)
        with self.assertRaises(e.FormatError): e.parse(bytes(d))
    def test_archive(self):
        body=b'ABCDEF'; h=b'demo.o/         '+b'0           '+b'0     '+b'0     '+b'100644  '+b'6         '+b'`\n'
        a,_=e.parse(b'!<arch>\n'+h+body); self.assertEqual(a['format'],'Archive'); self.assertEqual(a['members'][0]['name'],'demo.o'); self.assertEqual(a['members'][0]['size'],6)
    def test_raw_empty(self):
        for d in (b'',b'hello test',os.urandom(21)):
            a,_=e.parse(d); self.assertEqual(a['format'],'Raw')
    def test_structural_truncations(self):
        for data in (pe(),elf(),macho(),fat(macho())):
            for stop in (4,16,24,50,100,200):
                with self.assertRaises((ValueError,struct.error)): e.parse(data[:stop])
    def test_mutation_robustness(self):
        rng=random.Random(831)
        for source in (pe(),elf(),macho(),fat(macho())):
            for _ in range(80):
                data=bytearray(source)
                for __ in range(4): data[rng.randrange(min(len(data),512))]=rng.randrange(256)
                try: e.parse(bytes(data))
                except (ValueError,struct.error,OverflowError): pass
    def test_string_encodings(self):
        data=b'hello world\0'+ 'wide text'.encode('utf-16le')+b'\0\0'+ 'big endian'.encode('utf-16be')
        a,_=e.parse(data); strings=e.extract_strings(data,a)
        self.assertTrue(any(s['value']=='hello world' for s in strings)); self.assertTrue(any(s['encoding']=='UTF-16LE' for s in strings)); self.assertTrue(any(s['encoding']=='UTF-16BE' for s in strings))
    def test_entropy(self):
        self.assertEqual(e.entropy(b'\0'*100),0); self.assertEqual(e.entropy(bytes(range(256))),8)

class FileToolsTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.path=Path(self.tmp.name)/'data'; self.path.write_bytes(b'ABABA\x00\xff\x10hello\0')
    def tearDown(self): self.tmp.cleanup()
    def test_overlapping_search(self):
        r=e.search(self.path,'ABA'); self.assertEqual([h['offset'] for h in r['hits']],[0,2])
    def test_wildcard_search(self):
        r=e.search(self.path,'41 ?? 41','hex'); self.assertEqual([h['offset'] for h in r['hits']],[0,2])
        with self.assertRaises(ValueError): e.search(self.path,'GG','hex')
    def test_hex(self):
        self.assertIn('41 42 41 42 41',e.hex_view(self.path)['text'])
        with self.assertRaises(ValueError): e.hex_view(self.path,10000)
    def test_patch_and_diff(self):
        original=self.path.read_bytes(); dest=self.path.with_suffix('.patched'); digest=hashlib.sha256(original).hexdigest()
        r=e.patch(self.path,dest,1,'ff',digest); self.assertEqual(r['count'],1); self.assertEqual(self.path.read_bytes(),original)
        diff=e.compare(self.path,dest); self.assertEqual(diff['changed'],1); self.assertEqual(diff['runs'][0]['offset'],1)
        with self.assertRaises(FileExistsError): e.patch(self.path,dest,1,'ff')
        with self.assertRaises(ValueError): e.patch(self.path,self.path,1,'ff')
    def test_patch_hardlink_rejected(self):
        dest=self.path.with_suffix('.link'); os.link(self.path,dest)
        with self.assertRaises(ValueError): e.patch(self.path,dest,1,'ff')
    def test_patch_stale_hash_and_bounds(self):
        dest=self.path.with_suffix('.patched')
        with self.assertRaises(ValueError): e.patch(self.path,dest,0,'90','changed')
        with self.assertRaises(ValueError): e.patch(self.path,dest,100,'90')
    def test_diff_tail(self):
        p=self.path.with_suffix('.other'); p.write_bytes(self.path.read_bytes()+b'ABC'); r=e.compare(self.path,p); self.assertEqual(r['changed'],3); self.assertEqual(r['runs'][0]['size'],3)

class LLVMIntegration(unittest.TestCase):
    def test_real_macho_analysis(self):
        sample=Path(__file__).resolve().parents[1]/'Examples/asteria-sample'
        if not sample.exists(): self.skipTest('Build the training sample first')
        a=e.analyze(sample); self.assertEqual(a['format'],'Mach-O'); self.assertGreater(len(a['instructions']),50)
        self.assertTrue(any('score_input' in f['name'] for f in a['functions'])); self.assertTrue(any(x['kind']=='call' for x in a['xrefs']))
        self.assertTrue(any('training binary' in s['value'] for s in a['strings']))
    def test_pe_disassembly(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'sample.exe'; p.write_bytes(pe()); a=e.analyze(p)
            self.assertTrue(any(i['mnemonic']=='ret' for i in a['instructions']),a['warnings'])
    def test_real_cross_compiled_objects(self):
        with tempfile.TemporaryDirectory() as tmp:
            src=Path(tmp)/'object.c'; src.write_text('int plus(int x) { return x + 42; }')
            for target,fmt in [('x86_64-pc-windows-msvc','COFF'),('x86_64-unknown-linux-gnu','ELF'),('aarch64-unknown-linux-gnu','ELF')]:
                obj=Path(tmp)/(target+'.o'); subprocess.run(['/usr/bin/xcrun','clang','-target',target,'-g','-O0','-c',str(src),'-o',str(obj)],check=True,capture_output=True)
                a=e.analyze(obj); self.assertEqual(a['format'],fmt); self.assertGreater(len(a['instructions']),1,a['warnings'])

if __name__=='__main__': unittest.main(verbosity=2)
