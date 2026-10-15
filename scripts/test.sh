#!/bin/bash
set -euo pipefail
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"
export PYTHONDONTWRITEBYTECODE=1
if [[ ! -f Examples/asteria-sample || Examples/sample.c -nt Examples/asteria-sample || ! -d Examples/asteria-sample.dSYM ]]; then
  xcrun clang -g -O0 Examples/sample.c -o Examples/asteria-sample
fi
xcrun python3 -m unittest discover -s Tests -p 'test_engine.py' -v
xcrun python3 -m unittest discover -s Tests -p 'test_decompiler.py' -v
xcrun python3 -m unittest discover -s Tests -p 'test_recognition.py' -v
xcrun python3 -m unittest discover -s Tests -p 'test_session.py' -v
if [[ "${1:-}" == --debugger ]]; then xcrun python3 Tests/test_debugger.py; fi
