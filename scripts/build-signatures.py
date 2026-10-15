#!/usr/bin/env python3
"""Reproducibly build the bundled reference signatures using local Clang."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'Engine'))
import analysis
import recognition
targets = ['arm64-apple-macos14', 'x86_64-apple-macos14', 'aarch64-linux-gnu', 'x86_64-linux-gnu', 'i386-linux-gnu', 'x86_64-pc-windows-msvc', 'i686-pc-windows-msvc']
entries, seen, builds = [], set(), []
with tempfile.TemporaryDirectory() as directory:
    for target in targets:
        for opt in ('O0', 'O1', 'O2', 'Os'):
            obj = Path(directory) / 'reference.o'
            subprocess.run(['xcrun', 'clang', '-target', target, '-' + opt, '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-fno-vectorize', '-fno-slp-vectorize', '-fno-unroll-loops', '-c', str(ROOT / 'Examples/atlas_reference.c'), '-o', str(obj)], check=True)
            a = analysis.analyze(str(obj), recognize=False)
            learned = recognition.learn(a, 'Asteria reference C')
            builds.append(dict(target=target, optimization=opt, entries=learned['count'], skipped=learned['skipped']))
            for e in learned['pack']['entries']:
                e['name'] = recognition.canonical(e['name'])
                key = json.dumps(e, sort_keys=True)
                if key not in seen: seen.add(key); entries.append(e)
pack = dict(schema=recognition.SCHEMA, library='Asteria reference C · Clang scalar builds', entries=entries)
recognition.validate(pack)
destination = ROOT / 'Engine/signatures/reference.atlas.json'
destination.parent.mkdir(exist_ok=True)
destination.write_text(json.dumps(pack, indent=2) + '\n')
manifest = dict(compiler=subprocess.check_output(['xcrun','clang','--version'], text=True).splitlines()[0], source='Examples/atlas_reference.c', builds=builds, uniqueSignatures=len(entries))
(ROOT / 'Engine/signatures/manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(manifest, indent=2))
