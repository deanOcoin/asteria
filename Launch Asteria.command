#!/bin/bash
set -euo pipefail
PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
if [[ ! -d "$PROJECT_ROOT/build/Asteria.app" ]]; then "$PROJECT_ROOT/scripts/build.sh"; fi
open "$PROJECT_ROOT/build/Asteria.app"
