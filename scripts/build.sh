#!/bin/bash
set -euo pipefail
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"
CONFIGURATION="${1:-release}"
if [[ "$CONFIGURATION" != release && "$CONFIGURATION" != debug ]]; then
  echo 'Usage: scripts/build.sh [release|debug]' >&2
  exit 2
fi
if /usr/bin/pgrep -x Asteria >/dev/null; then
  echo 'Quit Asteria before rebuilding its signed app bundle, then run this script again.' >&2
  exit 1
fi
mkdir -p .cache/clang .cache/swift build
export CLANG_MODULE_CACHE_PATH="$PROJECT_ROOT/.cache/clang"
export SWIFTPM_MODULECACHE_OVERRIDE="$PROJECT_ROOT/.cache/swift"
export PYTHONDONTWRITEBYTECODE=1
if [[ ! -f Examples/asteria-sample || Examples/sample.c -nt Examples/asteria-sample || ! -d Examples/asteria-sample.dSYM ]]; then
  xcrun clang -g -O0 Examples/sample.c -o Examples/asteria-sample
fi
swift build --disable-sandbox --scratch-path .build -c "$CONFIGURATION"
APP="$PROJECT_ROOT/build/Asteria.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/Engine" "$APP/Contents/Resources/Examples"
cp ".build/$CONFIGURATION/Asteria" "$APP/Contents/MacOS/Asteria"
cp Engine/*.py "$APP/Contents/Resources/Engine/"
ditto Engine/signatures "$APP/Contents/Resources/Engine/signatures"
cp Examples/asteria-sample "$APP/Contents/Resources/Examples/asteria-sample"
cp Examples/sample.c "$APP/Contents/Resources/Examples/sample.c"
if [[ -d Examples/asteria-sample.dSYM ]]; then ditto Examples/asteria-sample.dSYM "$APP/Contents/Resources/Examples/asteria-sample.dSYM"; fi
cp scripts/Info.plist "$APP/Contents/Info.plist"
if [[ -f scripts/Asteria.icns ]]; then cp scripts/Asteria.icns "$APP/Contents/Resources/Asteria.icns"; fi
codesign --force --sign - "$APP"
echo "Built: $APP"
