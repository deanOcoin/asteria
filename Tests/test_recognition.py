import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'Engine'))
import analysis
import decompiler
import recognition
import worker


class AtlasTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.work = Path(cls.directory.name)
        cls.obj = cls.work / 'reference.o'
        subprocess.run(['xcrun', 'clang', '-target', 'arm64-apple-macos14', '-O1', '-ffreestanding', '-fno-builtin', '-fno-vectorize', '-fno-slp-vectorize', '-fno-unroll-loops', '-c', str(ROOT / 'Examples/atlas_reference.c'), '-o', str(cls.obj)], check=True)
        cls.named = analysis.analyze(str(cls.obj), recognize=False)
        cls.pack = recognition.learn(cls.named, 'Test reference')['pack']

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def stripped(self):
        a = copy.deepcopy(self.named)
        a['symbols'] = []; a['exports'] = []
        for f in a['functions']:
            old = f['name']; f['name'] = 'sub_' + f['address'][2:]
            for i in a['instructions']:
                if i['function'] == old: i['function'] = f['name']
        return a

    def test_complete_bodies_recognized(self):
        a = self.stripped(); r = recognition.recognize(a, [self.pack])
        self.assertEqual(len([m for m in r['matches'] if m['applied']]), 8)
        self.assertEqual({f['name'] for f in a['functions']}, {f['name'] for f in self.named['functions']})
        self.assertTrue(all(f['nameSource'] == 'signature' for f in a['functions']))

    def test_rebased_internal_branches(self):
        a = self.stripped(); delta = 0x70000000
        for f in a['functions']:
            f['address'] = hex(int(f['address'], 16) + delta); f['end'] = hex(int(f['end'], 16) + delta)
        import re
        for i in a['instructions']:
            i['address'] = hex(int(i['address'], 16) + delta)
            if i['target']:
                old = i['target']; i['target'] = hex(int(old, 16) + delta)
                i['operands'] = re.sub(r'0x[0-9a-fA-F]+', i['target'], i['operands'], count=1)
        self.assertEqual(len(recognition.recognize(a, [self.pack])['matches']), 8)

    def test_changed_instruction_not_recognized(self):
        a = self.stripped(); f = a['functions'][0]
        a['instructions'][1]['bytes'] = '00 00 00 00'
        r = recognition.recognize(a, [self.pack])
        self.assertFalse(any(m['address'] == f['address'] for m in r['matches']))

    def test_collision_never_picks_arbitrary_name(self):
        pack = copy.deepcopy(self.pack)
        collision = dict(pack['entries'][0], name='different_function'); pack['entries'].append(collision)
        a = self.stripped(); address = a['functions'][0]['address']
        r = recognition.recognize(a, [pack])
        self.assertTrue(any(m['address'] == address for m in r['ambiguities']))
        self.assertTrue(a['functions'][0]['name'].startswith('sub_'))

    def test_existing_symbols_preserved(self):
        a = copy.deepcopy(self.named); original = [f['name'] for f in a['functions']]
        r = recognition.recognize(a, [self.pack])
        self.assertEqual([f['name'] for f in a['functions']], original)
        self.assertTrue(r['matches']); self.assertFalse(any(m['applied'] for m in r['matches']))

    def test_wrong_architecture_rejected(self):
        a = self.stripped(); a['arch'] = 'x86_64'
        self.assertEqual(recognition.recognize(a, [self.pack])['matches'], [])

    def test_short_or_unresolved_functions_skipped(self):
        a = copy.deepcopy(self.named)
        a['instructions'][0].update(mnemonic='bl', kind='call', target='0xdeadbeef', operands='0xdeadbeef')
        learned = recognition.learn(a, 'References')
        self.assertLess(learned['count'], 8)
        self.assertTrue(any('unresolved' in line for line in learned['skipped']))

    def test_external_call_reference_must_match(self):
        a = copy.deepcopy(self.named)
        first = a['instructions'][0]
        first.update(mnemonic='bl', kind='call', target='0xdeadbeef', operands='0xdeadbeef')
        a['symbols'].append(dict(name='_known_helper', address='0xdeadbeef', kind='stub'))
        pack = recognition.learn(a, 'References')['pack']
        first['target'] = '0xcafebabe'; first['operands'] = '0xcafebabe'
        a['symbols'][-1]['address'] = '0xcafebabe'
        self.assertTrue(any(m['address'] == first['address'] for m in recognition.recognize(copy.deepcopy(a), [pack])['matches']))
        a['symbols'][-1]['name'] = '_wrong_helper'
        self.assertFalse(any(m['address'] == first['address'] for m in recognition.recognize(a, [pack])['matches']))

    def test_missing_file_bytes_do_not_match(self):
        a = self.stripped(); a['instructions'][0]['offset'] = -1
        self.assertFalse(any(m['address'] == a['functions'][0]['address'] for m in recognition.recognize(a, [self.pack])['matches']))

    def test_recover_multiple_starts_in_one_stripped_region(self):
        a = self.stripped(); a['functions'] = [dict(a['functions'][0], count=len(a['instructions']), end=a['instructions'][-1]['address'])]
        for i in a['instructions']: i['function'] = a['functions'][0]['name']
        recognition.recognize(a, [self.pack])
        starts = [f['address'] for f in a['functions']]
        self.assertEqual(len(starts), len(set(starts)))
        self.assertGreaterEqual(len([f for f in a['functions'] if f['nameSource'] == 'signature']), 5)
        for f in a['functions']:
            items = [i for i in a['instructions'] if i['function'] == f['name']]
            self.assertEqual(len(items), f['count']); self.assertEqual(items[0]['address'], f['address'])

    def test_install_is_idempotent_and_validated(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, ASTERIA_SIGNATURE_DIR=directory):
            path = Path(directory) / 'input.json'; path.write_text(json.dumps(self.pack))
            one = recognition.install(path); two = recognition.install(path)
            self.assertEqual(one['path'], two['path'])
            self.assertEqual(len(list(Path(directory).glob('*.atlas.json'))), 1)
            path.write_text('{"schema":"IDA"}')
            with self.assertRaises(ValueError): recognition.install(path)

    def test_malformed_pack_is_reported_without_breaking_analysis(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, ASTERIA_SIGNATURE_DIR=directory):
            (Path(directory) / 'bad.atlas.json').write_text('{')
            r = recognition.recognize(self.stripped())
            self.assertTrue(r['warnings']); self.assertGreater(r['signatures'], 0)

    def test_invalid_pack_bounds(self):
        for change in ({'ops': ['nop']}, {'size': 1}, {'name': 'bad name'}, {'ops': 'bad'}):
            pack = copy.deepcopy(self.pack); pack['entries'][0].update(change)
            with self.assertRaises(ValueError): recognition.validate(pack)

    def test_analyst_names_in_signature_and_call_sites(self):
        a = analysis.analyze(str(ROOT / 'Examples/asteria-sample'))
        score = next(f for f in a['functions'] if 'score_input' in f['name'])
        main = next(f for f in a['functions'] if f['name'] in ('main', '_main'))
        recognition.apply_names(a, {score['address']: 'calculate_score'})
        result = decompiler.decompile(a, score['address'])
        self.assertIn('calculate_score(', result['text'])
        self.assertIn('calculate_score(', decompiler.decompile(a, main['address'])['text'])
        self.assertIn('score_input', result['function']['originalName'])
        self.assertTrue(all(i['function'] == 'calculate_score' for i in result['instructions']))

    def test_rename_validation(self):
        for name in ('bad name', 'return', 'a' * 81):
            a = copy.deepcopy(self.named)
            with self.assertRaises(ValueError): recognition.apply_names(a, {a['functions'][0]['address']: name})
        a = copy.deepcopy(self.named)
        with self.assertRaises(ValueError): recognition.apply_names(a, {a['functions'][0]['address']: 'same', a['functions'][1]['address']: 'same'})

    def test_variable_provenance_and_rename_preserve_bytes(self):
        a = analysis.analyze(str(ROOT / 'Examples/asteria-sample'))
        f = next(f for f in a['functions'] if 'score_input' in f['name'])
        before = decompiler.decompile(a, f['address'])
        v = next(v for v in before['variables'] if v['kind'] == 'stack' and v['addresses'])
        after = decompiler.decompile(a, f['address'], {v['name']: 'user_score'})
        self.assertIn('user_score', after['text'])
        self.assertEqual(before['instructions'], after['instructions'])
        self.assertEqual(before['reverseMap'], after['reverseMap'])
        self.assertTrue(all(v['addresses'] for v in before['variables'] if v['kind'] == 'temporary'))

    def test_rpc_names_and_learning(self):
        path = str(ROOT / 'Examples/asteria-sample')
        a = analysis.analyze(path); f = a['functions'][0]
        result = worker.static(dict(action='decompile', path=path, function=f['address'], functionNames={f['address']: 'entry_named'}))
        self.assertIn('entry_named(', result['text'])
        learned = worker.static(dict(action='signatureLearn', path=path, library='Training', sha256=a['sha256']))
        self.assertGreater(learned['count'], 0)

    def test_real_stripped_macho_automatic_recognition(self):
        source = self.work / 'entry.c'; source.write_text('extern unsigned long strlen(const char *); int main(int argc, char **argv) { return argc > 1 ? (int)strlen(argv[1]) : 0; }')
        binary = self.work / 'stripped-reference'
        subprocess.run(['xcrun', 'clang', '-O1', '-fno-builtin', str(source), str(self.obj), '-o', str(binary)], check=True)
        named = analysis.analyze(str(binary), recognize=False)
        local_pack = recognition.learn(named, 'Linked reference')['pack']
        subprocess.run(['xcrun', 'strip', str(binary)], check=True)
        stripped = analysis.analyze(str(binary), recognize=False)
        self.assertFalse(any(f['name'] == '_strlen' for f in stripped['functions']))
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, ASTERIA_SIGNATURE_DIR=directory):
            pack = Path(directory) / 'linked.atlas.json'; pack.write_text(json.dumps(local_pack))
            result = analysis.analyze(str(binary))
            self.assertTrue(any(m['applied'] and recognition.canonical(m['name']) == 'strlen' for m in result['recognition']['matches']))
            self.assertEqual(len({f['address'] for f in result['functions']}), len(result['functions']))

    def test_real_pe_and_elf_containers_with_compiled_library_code(self):
        # real PE and ELF containers with Clang-built code pasted into minimal headers;
        # the fixtures are only inspected, never executed
        import struct
        from test_engine import pe, elf
        for format in ('PE', 'ELF'):
            for bits in (32, 64):
                with self.subTest(format=format, bits=bits):
                    target = ('x86_64' if bits == 64 else ('i686' if format == 'PE' else 'i386')) + ('-pc-windows-msvc' if format == 'PE' else '-linux-gnu')
                    obj = self.work / ('reference-' + target + '.o')
                    subprocess.run(['xcrun', 'clang', '-target', target, '-O1', '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-fno-vectorize', '-fno-slp-vectorize', '-fno-unroll-loops', '-c', str(ROOT / 'Examples/atlas_reference.c'), '-o', str(obj)], check=True)
                    a = analysis.analyze(str(obj), recognize=False)
                    f = next(f for f in a['functions'] if recognition.canonical(f['name']) == 'strlen')
                    items = recognition.trim_padding([i for i in a['instructions'] if i['function'] == f['name']])
                    code = bytes.fromhex(' '.join(i['bytes'] for i in items))
                    if format == 'PE':
                        data = bytearray(pe(bits)); o = 0x98; minimum = 112 if bits == 64 else 96
                        data[o + minimum:o + minimum + 128] = bytes(128)  # no import/export names
                        data[0x200:] = b'\xcc' * (len(data) - 0x200)
                        data[0x200:0x200 + len(code)] = code
                    else:
                        data = bytearray(elf(bits)); stride = 64 if bits == 64 else 40
                        names = b'\0.text\0.shstrtab\0.bss\0'
                        data[0x180:0x180 + len(names)] = names
                        # Section file offset/size fields differ by ELF class.
                        struct.pack_into('<Q' if bits == 64 else '<I', data, 0x200 + 2 * stride + (24 if bits == 64 else 16), 0x180)
                        struct.pack_into('<Q' if bits == 64 else '<I', data, 0x200 + stride + (32 if bits == 64 else 20), len(code))
                        data[0x100:0x100 + len(code)] = code
                    binary = self.work / ('library-' + format + str(bits))
                    binary.write_bytes(data)
                    result = analysis.analyze(str(binary))
                    self.assertEqual(result['format'], format)
                    self.assertTrue(any(m['applied'] and m['name'] == 'strlen' for m in result['recognition']['matches']), result['recognition'])

    def test_renaming_library_call_keeps_argument_and_pointer_semantics(self):
        a = analysis.analyze(str(ROOT / 'Examples/asteria-sample'))
        main = next(f for f in a['functions'] if f['name'] == '_main')
        puts = next(f for f in a['functions'] if f['name'] == '_puts')
        before = decompiler.decompile(a, main['address'])
        recognition.apply_names(a, {puts['address']: 'print_line'})
        after = decompiler.decompile(a, main['address'])
        self.assertEqual(before['text'].replace('puts(', 'print_line('), after['text'])
        self.assertEqual(before['reverseMap'], after['reverseMap'])

    def test_variable_name_cannot_shadow_called_function(self):
        a = analysis.analyze(str(ROOT / 'Examples/asteria-sample'))
        f = next(f for f in a['functions'] if 'score_input' in f['name'])
        result = decompiler.decompile(a, f['address'])
        with self.assertRaisesRegex(ValueError, 'collides with a function'):
            decompiler.decompile(a, f['address'], {result['variables'][0]['name']: 'strlen'})

    def test_overlapping_code_addresses_skip_matching(self):
        a = self.stripped(); a['instructions'].append(dict(a['instructions'][0], section='other'))
        r = recognition.recognize(a, [self.pack])
        self.assertFalse(r['matches']); self.assertIn('overlapping', r['warnings'][0])


if __name__ == '__main__': unittest.main()
