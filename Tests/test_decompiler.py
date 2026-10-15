import ctypes
import hashlib
import json
from pathlib import Path
import random
import re
import subprocess
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'Engine'))
import analysis
import decompiler as d
import patching
from test_engine import pe, fat, macho
ROOT=Path(__file__).resolve().parents[1]


def synthetic(lines,arch='arm64',fmt='Mach-O',bits=64):
    a=analysis.base_report(); a.update(arch=arch,format=fmt,bits=bits,sha256='test',selectedSlice=0)
    instructions=[]
    for n,line in enumerate(lines):
        m,_,p=line.partition(' '); addr=0x1000+n*4; kind=analysis.branch_kind(m)
        target=re.search(r'0x[0-9a-f]+',p) if kind in ('branch','jump','call') else None
        instructions.append(dict(address=hex(addr),offset=0x200+n*4,mnemonic=m,operands=p,function='test_fn',section='.text',kind=kind,target=target[0] if target else '',bytes='1f 20 03 d5'))
    a['instructions']=instructions; a['functions']=[dict(name='test_fn',address='0x1000',end=instructions[-1]['address'],count=len(instructions))]
    return a


def lift(a,opt=True):
    blocks=d.cfg(a['instructions']); lifter=d.Lifter(a,blocks).lift(); d.repair_stack_aliases(lifter); d.analyze_liveness(blocks)
    if opt:
        for b in blocks: d.optimize(b)
    return lifter


def evaluate(lifter,values,maxsteps=1000):
    env=dict(values); blocks={b.start:b for b in lifter.blocks}; cur=lifter.blocks[0].start
    def ev(e):
        mask=(1<<e.bits)-1
        if e.op=='const': return e.value
        if e.op=='var':
            if e.value not in env: raise AssertionError('Uninitialized '+e.value)
            return env[e.value]
        if e.op in ('unknown','load'): raise AssertionError('Unmodelled effect '+e.text())
        a=[ev(v) for v in e.args]
        if e.op=='cast': return a[0]&mask
        if e.op=='signed':
            n=a[0]&mask; return n-(1<<e.bits) if n&(1<<(e.bits-1)) else n
        if e.op=='select': return (a[1] if a[0] else a[2])&mask
        if e.op=='not': return int(not a[0])
        if e.op=='neg': return (-a[0])&mask
        if e.op=='inv': return (~a[0])&mask
        operations={'+':lambda:a[0]+a[1],'-':lambda:a[0]-a[1],'*':lambda:a[0]*a[1],'&':lambda:a[0]&a[1],'|':lambda:a[0]|a[1],'^':lambda:a[0]^a[1],
                    '<<':lambda:a[0]<<a[1],'>>':lambda:a[0]>>a[1],'==':lambda:int(a[0]==a[1]),'!=':lambda:int(a[0]!=a[1]),'<':lambda:int(a[0]<a[1]),'>':lambda:int(a[0]>a[1]),'<=':lambda:int(a[0]<=a[1]),'>=':lambda:int(a[0]>=a[1]),'&&':lambda:int(bool(a[0]) and bool(a[1])),'||':lambda:int(bool(a[0]) or bool(a[1]))}
        return operations[e.op]()&mask
    for _ in range(maxsteps):
        b=blocks[cur]
        for op in b.ops:
            if op.kind in ('assign','load','stack','output'): env[op.dst]=ev(op.expr)
            elif op.kind!='mechanic': raise AssertionError('Unsupported effect '+op.kind)
        t=b.term
        if t.kind=='return': return ev(t.expr)
        if t.kind=='jump': cur=t.target
        elif t.kind=='branch': cur=t.target if ev(t.expr) else next(n for n in b.succ if n!=t.target)
        else: raise AssertionError('Unexpected terminator '+t.kind)
    raise AssertionError('IR did not terminate')


class SemanticTests(unittest.TestCase):
    def check(self,lines,inputs,expected,arch='arm64',bits=64):
        a=synthetic(lines,arch,bits=bits)
        for optimized in (False,True): self.assertEqual(evaluate(lift(a,optimized),inputs),expected)
    def test_arm_zero_extending_word_write(self): self.check(['mov w0, #0xffffffff','ret'],{'x0':0xfedcba9876543210},0xffffffff)
    def test_arm_wrap_before_widen(self): self.check(['add w0, w0, #1','ret'],{'x0':0xffffffff},0)
    def test_arm_signed_compare(self):
        for a,b in [(0xffffffff,1),(0x80000000,0),(0x7fffffff,0xffffffff),(8,8)]:
            signed=lambda n:n-(1<<32) if n&(1<<31) else n
            self.check(['cmp w0, w1','cset w0, lt','ret'],{'x0':a,'x1':b},int(signed(a)<signed(b)))
    def test_arm_unsigned_compare(self): self.check(['cmp w0, w1','cset w0, lo','ret'],{'x0':0xffffffff,'x1':1},0)
    def test_arm_flags_survive_destination_write(self): self.check(['subs w0, w0, #5','cset w0, lt','ret'],{'x0':3},1)
    def test_arm_flags_across_block(self): self.check(['cmp w0, w1','b 0x1008','cset w0, lt','ret'],{'x0':0xffffffff,'x1':1},1)
    def test_x86_partial_and_high_byte(self): self.check(['mov ah, 0x12','mov al, 0x34','ret'],{'rax':0xdeadbeef00000000},0xdeadbeef00001234,'x86_64')
    def test_x86_zero_extend(self): self.check(['mov eax, 0x42','ret'],{'rax':0xffffffffffffffff},66,'x86_64')
    def test_x86_swap_parallel_outputs(self): self.check(['xchg rax, rdi','jmp 0x1008','add rax, rdi','ret'],{'rax':7,'rdi':29},36,'x86_64')
    def test_x86_increment_preserves_carry(self): self.check(['cmp edi, esi','inc edi','setb al','movzx eax, al','ret'],{'rdi':1,'rsi':2,'rax':0},1,'x86_64')
    def test_csel_preserves_compare(self): self.check(['cmp w0, w1','csinc w0, w0, w1, ge','ret'],{'x0':2,'x1':4},5)
    def test_stack_values_not_folded_across_store(self): self.check(['sub sp, sp, #16','str w0, [sp]','ldr w1, [sp]','str w2, [sp]','add w0, w1, w2','ret'],{'sp':0x100000,'x0':7,'x2':11},18)
    def test_opaque_barrier(self):
        r=d.decompile(synthetic(['mov w0, #5','fadd d0, d1, d2','add w0, w0, #1','ret']))
        self.assertEqual(r['coverage']['unsupported'],1); self.assertIn('asm_effect(',r['text']); self.assertIn('unknown_x0_after_',r['text']); self.assertNotIn('return 6;',r['text'])
    def test_cmov_memory_not_lazily_elided(self):
        r=d.decompile(synthetic(['cmp edi, esi','cmove eax, dword ptr [rdx]','ret'],'x86_64'))
        self.assertRegex(r['text'],r'v\d+ = load_u32'); self.assertNotRegex(r['text'],r'\? load_u32')
    def test_load_not_moved_across_call(self):
        r=d.decompile(synthetic(['ldr w19, [x1]','bl 0x3000','mov w0, w19','ret']))
        self.assertLess(r['text'].index('load_u32'),r['text'].index('sub_3000('))
    def test_unknown_architecture_rejected(self):
        with self.assertRaises(ValueError): d.decompile(synthetic(['ret'],'mips'))
    def test_mapping_is_total_and_bidirectional(self):
        a=synthetic(['mov w0, #7','add w0, w0, #3','ret']); r=d.decompile(a)
        self.assertEqual(r['coverage']['mapped'],3)
        for i in a['instructions']:
            self.assertIn(i['address'],r['reverseMap'])
            for line_id in r['reverseMap'][i['address']]:
                self.assertIn(i['address'],r['lines'][line_id]['addresses'])
                self.assertTrue(any(s['address']==i['address'] and s['offset']==i['offset'] for s in r['lines'][line_id]['spans']))
        ret=next(l for l in r['lines'] if l['kind']=='return'); self.assertEqual(len(ret['addresses']),3)
    def test_diamond_structures(self):
        r=d.decompile(synthetic(['cmp w0, #5','b.ge 0x1010','mov w0, #1','b 0x1014','mov w0, #2','ret']))
        self.assertIn('if (',r['text']); self.assertIn('else',r['text']); self.assertNotIn('goto',r['text'])
    def test_names_validate_and_preserve_maps(self):
        a=synthetic(['add w0, w0, #1','ret']); r=d.decompile(a,names={'x0':'counter'})
        self.assertIn('counter',r['text']); self.assertEqual(r['reverseMap'],d.decompile(a)['reverseMap'])
        for name in ('x; system()', 'if','9foo'):
            with self.assertRaises(ValueError): d.decompile(a,names={'x0':name})
    def test_resource_limit(self):
        with self.assertRaises(ValueError): d.decompile(synthetic(['nop']*3001+['ret']))
    def test_overlapping_stack_is_explicit(self):
        r=d.decompile(synthetic(['str x0, [sp, #-8]','ldrb w0, [sp, #-7]','ret']))
        self.assertIn('entry_stack',r['text']); self.assertTrue(any('Overlapping' in s for s in r['diagnostics']))

    def test_compare_instruction_is_mapped_to_condition(self):
        r=d.decompile(synthetic(['cmp w0, #5','cset w0, lt','ret']))
        line=next(l for l in r['lines'] if l['kind']=='return')
        self.assertIn('0x1000',line['addresses'])
    def test_block_input_snapshot_before_output(self):
        self.check(['mov w1, #0','add w1, w1, #1','cmp w0, #1','sub w0, w0, #1','b.ne 0x1004','mov w0, w1','ret'],{'x0':3},3)
    def test_x86_decrement_preserves_carry(self):
        self.check(['cmp edi, esi','dec edi','setb al','movzx eax, al','ret'],{'rdi':1,'rsi':2,'rax':0},1,'x86_64')
    def test_arithmetic_overflow_flags(self):
        self.check(['adds w0, w0, #1','cset w0, vs','ret'],{'x0':0x7fffffff},1)
        self.check(['adds w0, w0, #1','cset w0, lt','ret'],{'x0':0x7fffffff},0)
    def test_calls_do_not_reuse_clobbered_arguments(self):
        r=d.decompile(synthetic(['mov x0, #1','bl 0x3000','mov x0, #2','bl 0x4000','ret']))
        second=next(l for l in r['lines'] if 'sub_4000(' in l['text'])
        self.assertIn('sub_4000(2)',second['text']); self.assertNotIn('unknown_',second['text'])
    def test_parity_condition_is_explicitly_unsupported(self):
        r=d.decompile(synthetic(['test edi, edi','setp al','ret'],'x86_64'))
        self.assertGreater(r['coverage']['unsupported'],0); self.assertIn('unknown_condition_p',r['text'])
    def test_segment_memory_stays_explicit(self):
        r=d.decompile(synthetic(['mov rax, qword ptr fs:[0x28]','ret'],'x86_64'))
        self.assertEqual(r['coverage']['unsupported'],1); self.assertIn('asm_effect',r['text'])
    def test_names_cannot_collide(self):
        with self.assertRaises(ValueError): d.decompile(synthetic(['add x0, x0, x1','ret']),names={'x0':'arg2'})
    def test_unmapped_bytes_are_not_patch_spans(self):
        a=synthetic(['mov w0, #7','ret']); a['instructions'][0]['offset']=-1
        r=d.decompile(a)
        self.assertTrue(all(span['offset']>=0 for line in r['lines'] for span in line['spans']))
        self.assertTrue(any('no proven file bytes' in s for s in r['diagnostics']))

    def test_stack_address_escaping_call_disables_local_recovery(self):
        r=d.decompile(synthetic(['sub sp, sp, #16','str w1, [sp]','mov x0, sp','bl 0x3000','ldr w0, [sp]','ret']))
        self.assertTrue(any('Stack recovery is disabled' in s for s in r['diagnostics']))
        self.assertIn('store_u32',r['text']); self.assertIn('load_u32',r['text'])
    def test_call_clobbers_affine_return_register(self):
        r=d.decompile(synthetic(['sub sp, sp, #16','mov x0, sp','bl 0x3000','ldr w0, [x0]','ret']))
        self.assertIn('load_u32(call_',r['text'])
    def test_cdecl_byte_argument_is_part_of_word_parameter(self):
        r=d.decompile(synthetic(['movsx eax, byte ptr [esp + 4]','ret'],'x86',fmt='ELF',bits=32))
        self.assertIn('uint32_t arg1',r['text']); self.assertIn('(int8_t)',r['text'])
    def test_unsupported_effects_disable_stack_slot_assumptions(self):
        r=d.decompile(synthetic(['sub sp, sp, #16','str w0, [sp]','fadd d0, d1, d2','ldr w0, [sp]','ret']))
        self.assertTrue(any('Stack recovery is disabled' in s for s in r['diagnostics'])); self.assertIn('unknown_sp_after_',r['text'])

    def test_string_prefix_is_not_substituted_as_complete_literal(self):
        a=synthetic(['mov x0, #0x2000','bl 0x3000','ret'])
        a['functions'].append(dict(name='_puts',address='0x3000',end='0x3000',count=0))
        a['strings']=[dict(address='0x2000',value='truncated prefix',encoding='ASCII',terminated=False)]
        self.assertNotIn('"truncated prefix"',d.decompile(a,'test_fn')['text'])
        a['strings'][0]['terminated']=True
        self.assertIn('"truncated prefix"',d.decompile(a,'test_fn')['text'])


class PatchTests(unittest.TestCase):
    def ins(self,raw,asm='b.eq 0x1010'):
        m,_,p=asm.partition(' '); return dict(address='0x1000',bytes=raw,mnemonic=m,operands=p)
    def test_arm_branch_rewrites(self):
        i=self.ins('80 00 00 54')
        self.assertEqual(patching.rewrite('arm64',i,'invert').hex(),'81000054')
        self.assertEqual(patching.rewrite('arm64',i,'always').hex(),'04000014')
        self.assertEqual(patching.rewrite('arm64',i,'nop').hex(),'1f2003d5')
    def test_x86_near_branch_adjusts_displacement(self):
        i=self.ins('0f 85 04 00 00 00','jne 0x100a')
        self.assertEqual(patching.rewrite('x86_64',i,'always').hex(),'e90500000090')
        self.assertEqual(patching.rewrite('x86_64',i,'invert').hex(),'0f8404000000')
    def test_immediate_bounds(self):
        i=self.ins('40 05 80 52','mov w0, #42')
        self.assertEqual(patching.rewrite('arm64',i,'immediate','7').hex(),'e0008052')
        with self.assertRaises(ValueError): patching.rewrite('arm64',i,'immediate','65536')
        i=self.ins('83 f8 01','cmp eax, 1')
        with self.assertRaises(ValueError): patching.rewrite('x86_64',i,'immediate','128')
    def test_preview_stale_and_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'answer.exe'; p.write_bytes(pe()); a=analysis.analyze(p); ins=next(i for i in a['instructions'] if i['mnemonic']=='mov')
            with self.assertRaises(ValueError): patching.preview(p,ins['address'],'immediate','7',expected_hash='stale')
            preview=patching.preview(p,ins['address'],'immediate','7',expected_hash=a['sha256'])
            self.assertIn('0x7',preview['replacement']); out=p.with_suffix('.patched')
            analysis.patch(p,out,preview['offset'],preview['after'],preview['sha256'])
            self.assertEqual(p.read_bytes(),pe()); self.assertNotEqual(out.read_bytes(),pe())

    def test_backward_branch_preserves_target(self):
        i=self.ins('e0 ff ff 54','b.eq 0xffc')
        raw=patching.rewrite('arm64',i,'always')
        self.assertEqual(raw.hex(),'ffffff17')
    def test_wrong_rewrite_rejected(self):
        with self.assertRaises(ValueError): patching.rewrite('arm64',self.ins('c0 03 5f d6','ret'),'invert')


class DecoderTests(unittest.TestCase):
    def test_last_instruction_exact_length(self):
        with tempfile.TemporaryDirectory() as tmp:
            src=Path(tmp)/'last.s'; src.write_text('.text\n.globl answer\nanswer:\nmovabs $0x123456789abcdef0, %rax\n')
            obj=Path(tmp)/'last.o'; subprocess.run(['xcrun','clang','-target','x86_64-unknown-linux-gnu','-c',str(src),'-o',str(obj)],check=True,capture_output=True)
            a=analysis.analyze(obj); self.assertEqual(len(bytes.fromhex(a['instructions'][-1]['bytes'])),10)
    def test_universal_source_offsets(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'fat'; p.write_bytes(fat(macho())); a=analysis.analyze(p); r=d.decompile(a)
            for line in r['lines']:
                for span in line['spans']: self.assertEqual(p.read_bytes()[span['offset']:span['offset']+span['size']],bytes.fromhex(span['bytes']))
    def test_training_loop_and_import_names(self):
        a=analysis.analyze(ROOT/'Examples/asteria-sample'); r=d.decompile(a,'_score_input')
        self.assertEqual(r['coverage']['unsupported'],0); self.assertEqual(r['coverage']['loops'],1)
        self.assertIn('strlen(',r['text']); self.assertIn('&&',r['text']); self.assertNotIn('goto',r['text'])


class CompiledCorpusTests(unittest.TestCase):
    """Compile the original C and the emitted pseudocode separately, then compare behaviour.
    Checking rendered code also covers region structuring, width rendering and statement order, not just the IR."""
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(); cls.directory=Path(cls.tmp.name)
        native=cls.directory/'original.dylib'
        subprocess.run(['xcrun','clang','-dynamiclib','-O1',str(ROOT/'Tests/fixtures/decompiler_corpus.c'),'-o',str(native)],check=True,capture_output=True)
        cls.native_path=str(native); cls.checked=0
    @classmethod
    def tearDownClass(cls): cls.tmp.cleanup()
    def test_cross_architecture_rendered_semantics(self):
        targets=['arm64-apple-macos14','x86_64-apple-macos14','aarch64-unknown-linux-gnu','x86_64-unknown-linux-gnu','x86_64-pc-windows-msvc','i386-unknown-linux-gnu','i686-pc-windows-msvc']
        rng=random.Random(8801)
        for target in targets:
            for opt in (0,1,2):
                with self.subTest(target=target,opt=opt):
                    obj=self.directory/(target+str(opt)+'.o')
                    subprocess.run(['xcrun','clang','-target',target,'-O'+str(opt),'-fno-vectorize','-fno-slp-vectorize','-fno-unroll-loops','-c',str(ROOT/'Tests/fixtures/decompiler_corpus.c'),'-o',str(obj)],check=True,capture_output=True)
                    a=analysis.analyze(obj); code='#include <stdint.h>\n#include <stdbool.h>\n#include <string.h>\n'; results=[]
                    for width in (8,16,32,64):
                        code+='static uint%d_t load_u%d(uint64_t p) { uint%d_t x; memcpy(&x,(void*)(uintptr_t)p,sizeof x); return x; }\n'%(width,width,width)
                        code+='static void store_u%d(uint64_t p,uint%d_t x) { memcpy((void*)(uintptr_t)p,&x,sizeof x); }\n'%(width,width)
                    for f in a['functions']:
                        if 'dc_' not in f['name'] or (a['bits']==32 and 'dc_wide' in f['name']): continue
                        r=d.decompile(a,f['address']); self.assertEqual(r['coverage']['unsupported'],0,(f['name'],r['text']))
                        self.assertEqual(r['coverage']['mapped'],r['coverage']['total'])
                        results.append(r)
                        # Supply a concrete entry-stack backing store to the test harness.
                        # Other incoming machine registers are zeroed, not inferred as arguments.
                        rendered=r['text'].replace('uint64_t entry_stack; /* incoming machine state */','uint8_t backing[2048] = {0}; uint64_t entry_stack = (uintptr_t)&backing[1024];')
                        rendered=re.sub(r'(uint(?:32|64)_t (?:rax|rcx|rdx|rbx|rsi|rdi|rsp|rbp|x[0-9]+)); /\* incoming machine state \*/',r'\1 = 0; /* harness machine state */',rendered)
                        code+=rendered+'\n'
                    self.assertEqual(len(results),8 if a['bits']==32 else 9)
                    output=self.directory/(target+str(opt)+'.c'); output.write_text(code)
                    lib=output.with_suffix('.dylib')
                    build=subprocess.run(['xcrun','clang','-dynamiclib','-O0','-Werror=implicit-function-declaration',str(output),'-o',str(lib)],capture_output=True,text=True)
                    if build.returncode:
                        artifact=ROOT/'work/decompiler'/('failed-'+target+str(opt)+'.c'); artifact.write_text(code)
                    self.assertEqual(build.returncode,0,build.stderr)
                    cases=[]
                    for r in results:
                        name=d.ident(r['function']['name'])
                        pairs=[(0,0),(1,2),(0xffffffff,1),(0x80000000,0x7fffffff),(40,99),(41,100)]+[(rng.randrange(2**32),rng.randrange(2**32)) for _ in range(45)]
                        if name=='dc_while': pairs=[(x%40,y) for x,y in pairs]
                        if name=='dc_wide': pairs += [(0xffffffffffffffff,0xffffffffffffffff),(0x8000000000000000,13)]+[(rng.randrange(2**64),rng.randrange(2**64)) for _ in range(30)]
                        mask=0xffffffffffffffff
                        cases.append(dict(name=name,pairs=pairs,mask=mask))
                    query=dict(original=self.native_path,generated=str(lib),cases=cases)
                    try:
                        run=subprocess.run([sys.executable,str(ROOT/'Tests/run_decompiled_native.py')],input=json.dumps(query),text=True,capture_output=True,timeout=6)
                        if run.returncode:
                            (ROOT/'work/decompiler'/('failed-'+target+str(opt)+'.c')).write_text(code)
                        self.assertEqual(run.returncode,0,run.stdout[-2000:]+run.stderr)
                    except subprocess.TimeoutExpired as error:
                        (ROOT/'work/decompiler'/('failed-'+target+str(opt)+'.c')).write_text(code)
                        self.fail('Native differential timed out: '+str(error.stdout[-1000:]))
                    type(self).checked+=sum(len(c['pairs']) for c in cases)
        print('Differential rendered-C checks:',self.checked)

if __name__=='__main__': unittest.main(verbosity=2)
