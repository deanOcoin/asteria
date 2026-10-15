# Asteria 0.2 decompiler verification

Verified 8 September 2026 on Apple Silicon macOS 26.6.2 with Xcode 26.6.

## Delivered

- Original Python decompiler: typed expressions, scalar ARM64/x64/x86 lifters, local SSA temporaries, block-input snapshots, register liveness, stack storage recovery, value simplification and structured control flow.
- Native SwiftUI linked pseudocode/disassembly view with exact instruction bytes and whole-file offsets, bidirectional selection, wrapping, optional mechanics, diagnostics, IR inspection, variable names and exports.
- Original bounded instruction rewrite encoders; LLVM verifies replacement decoding before copy export.
- Hash-aware requests/caches, backward-compatible project names, CLI access, design and user documentation.
- Decoder now reads exact instruction lengths from LLVM output, including a final multi-byte x86 instruction. Mach-O indirect symbol tables resolve import stubs.

## Automated results

**69 tests passed:** 24 existing parser/file-tool/LLVM regression tests and 45 decompiler/patch/decoder tests.

The rendered-code corpus covers **183 decompiled functions** in **21 target/optimization combinations**, with **9,813 successful differential executions**. Targets:

| Container | Target |
|---|---|
| Mach-O | arm64-apple-macos14 |
| Mach-O | x86_64-apple-macos14 |
| ELF | aarch64-unknown-linux-gnu |
| ELF | x86_64-unknown-linux-gnu |
| ELF | i386-unknown-linux-gnu |
| COFF | x86_64-pc-windows-msvc |
| COFF | i686-pc-windows-msvc |

Each target is compiled at O0, O1 and O2. Vectorization and loop unrolling are disabled to exercise the current scalar lifters. The corpus includes integer arithmetic, signed/unsigned selection, ranges/short-circuit conditions, loops and early exits, byte extension, and 64-bit arithmetic. The 32-bit targets exclude the 64-bit paired-return function, which is outside current return-type recovery.

**Method:** compile the original C into a native Mac reference library; cross-compile objects for each target; decode and decompile those objects; compile the emitted C-like text into another native Mac library; compare outputs over deterministic boundary/random inputs. Memory helper definitions and a concrete backing store for entry-stack accesses are provided by the harness. This executes emitted pseudocode on the Mac; it does not execute Windows/Linux binaries or establish cross-OS debugging support. Child-process timeouts catch nonterminating or crashing generated code.

Additional regressions cover partial/high x86 registers, zero extension, width wrapping, signed comparisons, carry preservation, overflow flags, flags across blocks, snapshots before outgoing register updates, memory ordering, conditional-move loads, unsupported effects, stack escape/call clobbers, overlapping stack widths, scalar cdecl parameters, safe string-literal substitution, naming collisions, complete reverse mappings, instruction-length accuracy, universal offsets, patch encodings, stale hashes and copy preservation.

**Swift integration passed:** analysis and decompiler Codable payloads, provenance, verified branch inversion preview, old-project decoding, new-project variable-name round-trip, persistent LLDB framing, target setup, breakpoint resolution and console response.

**Release build passed.** `codesign --verify --deep --strict build/Asteria.app` passed. No downloaded runtime packages or external decompiler dependencies were added.

## Native app checks

- Loaded the real training binary; `_score_input` reports **64/64 mapped instructions**, one recovered loop, and no unsupported scalar instructions.
- Inspected the wrapped pseudocode/disassembly layout and selected the loop condition. The corresponding load/compare/branch instructions were linked; selecting the branch performed the reverse lookup.
- **Hex / Patch** opened at file offset **0x52c**, with context identifying VA **0x10000052c** and the exact original bytes **82 05 00 54**. Returning to pseudocode retained selection.
- Branch inversion preview decoded **83 05 00 54** as `b.lo` to the same target **0x1000005dc**.
- A separate NOP preview decoded **1f 20 03 d5**. Exported the patched training copy through the native save dialog. File verification proved equal lengths (50,560 bytes), the intended replacement span, all bytes outside the span unchanged, and the original SHA unchanged. Fresh analysis decoded `nop` at offset 0x52c. The altered training program was not executed.
- Renamed recovered `local_1c_u32` to **score** in the Variables sheet. The pseudocode updated while retaining its mapping. Saved the project through the app and verified the stored name map and original binary hash on disk.
- During development, a save-dialog attempt became unusable after the app bundle had been rebuilt while the app was running. A clean launch of the completed, signed release successfully saved both the project and patched copy. Quit the app before rebuilding its bundle in place.

## Limits of the evidence

The corpus is intentionally focused; passing it is not a proof of general decompiler correctness or parity with Hex-Rays. No benchmark comparison claiming superiority has been performed. Real-world optimized/obfuscated binaries, complex aliasing, language runtimes and uncommon ABI conventions need broader validation. SIMD/floating point, jump-table recovery, full source typing, multi-register returns and general relocation-aware assembly remain outside this release. Pointer-authentication/landing-pad instructions are preserved as machine bookkeeping; their runtime checks are not simulated by the scalar pseudocode.

The existing remote-debugging and core-dump paths were not reclassified as verified by this work. The prior release's detailed LLDB execution verification remains in `docs/RELEASE_NOTES.md`.

Reproduce with `scripts/test.sh` and the Swift client command in README.md. Test sources are in `Tests/test_decompiler.py`, `Tests/run_decompiled_native.py`, and `Tests/fixtures/decompiler_corpus.c`.
