# Asteria 0.3 verification

Date: 8 September 2026. Environment: Apple Silicon Mac, macOS 26.6.2, Xcode 26.6 tools.

## Automated checks

- 24 existing format, file-tool and worker tests pass.
- 45 existing decompiler tests pass, including 9,813 differential rendered-C executions across 183 recovered functions from 21 target/optimization configurations.
- 22 Atlas and naming tests pass. They cover complete bodies, rebasing, altered instructions, named external references, collisions, symbol precedence, malformed and oversized entries, duplicate imports, byte provenance, function/call-site overrides, library-call argument preservation, and variable/function name collisions.
- Automatic recognition is verified on a genuinely stripped linked Mach-O and on PE32, PE32+, ELF32 and ELF64 containers containing Clang-compiled reference `strlen` code. The PE/ELF fixtures are parsed and decoded on the Mac; they are not executed as foreign operating-system processes.
- Workspace smoke checks pass for both Follow directions, independent function and line selection, explicit jumps, F2 target resolution, variable and function rename application, invalid-name rollback, stable provenance, project persistence and old project compatibility.

The bundled pack is reproducible with `xcrun python3 scripts/build-signatures.py`. It contains 119 unique signatures from 28 recorded builds. `Engine/signatures/manifest.json` records the compiler and target configurations.

## Native interaction checks

- Selected a function in the native function list and invoked F2.
- Renamed `_score_input` to `calculate_score`; the function list and pseudocode declaration updated.
- Clicked the `local_1c_u32` identifier in pseudocode and invoked F2; the dialog selected that exact variable.
- Renamed it to `score`; declarations and all visible uses updated while the selected instruction remained at VA `0x100000508`, file offset `0x508`.
- Turned Follow off and selected `_main` in the disassembly-only function picker; pseudocode stayed on `calculate_score`.
- Selected instruction `0x100000608` and invoked F2; the dialog identified `_main` and offered recovered values correlated with that instruction.
- Opened the stripped recognition demonstration in the native application: 119 signatures loaded, eight names applied, zero ambiguities.
- Inspected native accessibility help for navigation, Follow, offsets, ABI, patching and rename controls. Visually reviewed the decompiler layout.

## Scope of the evidence

These checks establish the implemented navigation, naming, persistence and conservative signature-matching paths. They do not establish universal library recognition or source recovery. The starter pack covers Asteria's original reference C implementations, not every vendor's runtime library. Unsupported instructions and ambiguous recovered storage remain explicitly identified by the decompiler.

To rebuild, quit Asteria first, run `scripts/build.sh`, wait for completion, then launch `build/Asteria.app`. The build script now checks for a running Asteria process before replacing its signed bundle.
