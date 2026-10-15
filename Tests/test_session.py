"""Regression checks for bounded analysis reuse and the long-padding slowdown."""
import copy
import hashlib
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
import recognition
from session import AnalysisSession
import worker


def fixture(path, slice_index=0):
    return dict(path=str(path), sha256=hashlib.sha256(Path(path).read_bytes()).hexdigest(),
                selectedSlice=slice_index,
                functions=[dict(name='first', address='0x10', end='0x10', count=1),
                           dict(name='second', address='0x20', end='0x20', count=1)],
                instructions=[dict(function='first', address='0x10'), dict(function='second', address='0x20')],
                xrefs=[dict(function='first', source='0x10', target='0x20'),
                       dict(function='second', source='0x20', target='0x10')])


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'binary'
        self.path.write_bytes(b'first binary content')
        self.analyzer = patch('session.analysis.analyze', side_effect=fixture).start()
        self.addCleanup(patch.stopall)
        self.signatures = patch('session.signature_identity', return_value=('initial',)).start()
        self.session = AnalysisSession()

    def test_repeated_requests_analyze_once(self):
        first = self.session.analyze(self.path)
        self.assertIs(first, self.session.analyze(self.path))
        self.assertEqual(self.analyzer.call_count, 1)

    def test_rename_overlays_do_not_pollute_cached_analysis(self):
        base = self.session.analyze(self.path); snapshot = copy.deepcopy(base)
        one = self.session.analyze(self.path, function_names={'0x10': 'analyst_name'})
        two = self.session.analyze(self.path, function_names={'0x10': 'other_name'})
        self.assertEqual(one['instructions'][0]['function'], 'analyst_name')
        self.assertEqual(two['instructions'][0]['function'], 'other_name')
        self.assertEqual(one['xrefs'][0]['function'], 'analyst_name')
        self.assertEqual(base, snapshot)
        self.assertEqual(self.analyzer.call_count, 1)

    def test_swapping_names_keeps_instruction_and_reference_owners(self):
        a = self.session.analyze(self.path, function_names={'0x10': 'second', '0x20': 'first'})
        self.assertEqual([i['function'] for i in a['instructions']], ['second', 'first'])
        self.assertEqual([i['function'] for i in a['xrefs']], ['second', 'first'])

    def test_invalid_names_leave_cache_usable(self):
        before = copy.deepcopy(self.session.analyze(self.path))
        with self.assertRaises(ValueError):
            self.session.analyze(self.path, function_names={'0x10': 'return'})
        self.assertEqual(before, self.session.analyze(self.path))
        self.assertEqual(self.analyzer.call_count, 1)

    def test_same_size_edit_with_restored_mtime_is_detected(self):
        before = self.session.analyze(self.path); stat = self.path.stat()
        self.path.write_bytes(b'other binary content')
        os.utime(self.path, ns=(stat.st_atime_ns, stat.st_mtime_ns))
        after = self.session.analyze(self.path)
        self.assertNotEqual(before['sha256'], after['sha256'])
        self.assertEqual(self.analyzer.call_count, 2)

    def test_deleted_file_cannot_serve_stale_analysis(self):
        self.session.analyze(self.path); self.path.unlink()
        with self.assertRaises((OSError, ValueError)):
            self.session.analyze(self.path)

    def test_slices_and_signature_updates_invalidate(self):
        self.session.analyze(self.path, 0); self.session.analyze(self.path, 1)
        self.signatures.return_value = ('new pack',)
        self.session.analyze(self.path, 1)
        self.assertEqual(self.analyzer.call_count, 3)

    def test_explicit_rescan_refreshes(self):
        self.session.analyze(self.path); self.session.analyze(self.path, refresh=True)
        self.assertEqual(self.analyzer.call_count, 2)

    def test_file_changed_during_analysis_is_rejected(self):
        self.analyzer.side_effect = lambda *args: dict(fixture(*args), sha256='changed')
        with self.assertRaisesRegex(ValueError, 'changed'):
            self.session.analyze(self.path)
        self.assertFalse(self.session.entries)

    def test_lru_evicts_least_recently_used_file(self):
        paths = [self.path]
        for n in range(3):
            path = self.path.with_name(str(n)); path.write_bytes(bytes([n]) * 20); paths.append(path)
        for p in paths[:3]: self.session.analyze(p)
        self.session.analyze(paths[0]); self.session.analyze(paths[3]); self.session.analyze(paths[0])
        self.assertEqual(self.analyzer.call_count, 4)
        self.session.analyze(paths[1]); self.assertEqual(self.analyzer.call_count, 5)
        self.assertEqual(len(self.session.entries), 3)

    def test_instruction_budget_evicts_even_below_file_limit(self):
        self.session.max_instructions = 3
        self.session.analyze(self.path)
        other = self.path.with_name('other'); other.write_bytes(b'new binary')
        self.session.analyze(other)
        self.assertEqual(len(self.session.entries), 1)

    def test_hash_guard_applies_on_cache_hits(self):
        with patch.object(worker, 'session', self.session):
            a = worker.analyzed(dict(path=str(self.path)))
            self.assertEqual(worker.analyzed(dict(path=str(self.path), sha256=a['sha256'])), a)
            with self.assertRaisesRegex(ValueError, 'changed'):
                worker.analyzed(dict(path=str(self.path), sha256='old hash'))
        self.assertEqual(self.analyzer.call_count, 1)


class RecognitionComplexityTests(unittest.TestCase):
    def test_padding_scan_is_linear(self):
        class CountedInstruction(dict):
            reads = 0
            def __getitem__(self, key):
                if key == 'mnemonic': type(self).reads += 1
                return super().__getitem__(key)
        count = 6000
        items = [CountedInstruction(address=hex(0x1000 + n), mnemonic='ret' if n == 0 else 'int3',
                                    kind='return' if n == 0 else 'other', target='', function='sub_1000',
                                    section='.text', bytes='c3' if n == 0 else 'cc', operands='', offset=n)
                 for n in range(count)]
        a = dict(arch='x86_64', bits=64, endian='little', instructions=items, symbols=[], imports=[],
                 functions=[dict(name='sub_1000', address='0x1000', end=items[-1]['address'], count=count)], xrefs=[])
        result = recognition.recognize(a, [])
        self.assertEqual(result['matches'], [])
        self.assertLess(CountedInstruction.reads, 12 * count, 'Do not walk back through padding for each instruction')


class PersistentProtocolTests(unittest.TestCase):
    def test_multiple_requests_errors_and_shutdown_in_one_worker(self):
        process = subprocess.Popen([sys.executable, '-B', str(ROOT / 'Engine/worker.py'), '--static-session'],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: process.kill() if process.poll() is None else None)
        path = str(ROOT / 'Examples/asteria-sample')
        def call(identifier, **query):
            process.stdin.write(json.dumps(dict(id=identifier, **query)) + '\n'); process.stdin.flush()
            response = json.loads(process.stdout.readline()); self.assertEqual(response['id'], identifier)
            return response
        a = call(1, action='analyze', path=path)['result']
        d = call(2, action='decompile', path=path, function=a['functions'][0]['address'], sha256=a['sha256'])
        self.assertTrue(d['ok']); self.assertEqual(d['result']['sha256'], a['sha256'])
        self.assertFalse(call(3, action='decompile', path=path, function='0xdeadbeef')['ok'])
        self.assertEqual(call(4, action='analyze', path=path)['result'], a)
        self.assertTrue(call(5, action='shutdown')['ok'])
        process.communicate(timeout=10); self.assertEqual(process.returncode, 0)

    def test_decompile_and_patch_preview_reuse_without_mutating_base(self):
        session = AnalysisSession()
        path = ROOT / 'Examples/asteria-sample'
        original = analysis.analyze
        with patch('session.analysis.analyze', wraps=original) as analyze, patch.object(worker, 'session', session):
            a = worker.static(dict(action='analyze', path=path)); before = copy.deepcopy(a)
            f = next(f for f in a['functions'] if 'score_input' in f['name'])
            d = worker.static(dict(action='decompile', path=path, function=f['address'], functionNames={f['address']: 'score'}))
            branch = next(i for i in d['instructions'] if i['mnemonic'] == 'b.hs')
            preview = worker.static(dict(action='patchPreview', path=path, address=branch['address'], kind='invert', sha256=a['sha256']))
            self.assertNotEqual(preview['before'], preview['after'])
            self.assertEqual(a, before)
            # One cached source analysis; one fresh analysis of the temporary
            # patched copy for verification, with library recognition disabled.
            self.assertEqual(analyze.call_count, 2)
            self.assertFalse(analyze.call_args.kwargs['recognize'])


if __name__ == '__main__': unittest.main()
