# Asteria decompiler: design and implementation plan

## Product contract

An original, local decompiler turns decoded instructions into inspectable C-like statements. The native workspace pairs each statement with all contributing instructions, their virtual addresses, exact bytes, and whole-file offsets. A statement is not assumed to correspond to one contiguous patch. Every instruction remains accounted for, including compiler bookkeeping, discarded results, and operations whose semantics are not supported.

This is a substantial first implementation, not a claim of Hex-Rays parity. Source variable names, full C/C++ types, library prototypes, and source-equivalent recompilation are not generally recoverable. Unsupported effects must be explicit rather than replaced with plausible code.

## Pipeline

1. **Decode and identify.** LLVM supplies instruction boundaries. Read exactly those bytes from the matching section of the selected slice. Retain section, VA, file offset, and hash. Reject ambiguous function addresses.
2. **Build CFG.** Split on targets and terminators, record conditional/fallthrough edges, predecessors and reachable blocks. Bound function size before recursive processing.
3. **Lift.** Original ARM64 and x86/x64 lifters produce typed expressions and effectful operations. Integer widths, subregister writes, memory access widths, calls, flags, and unsupported effects are represented explicitly. Local single-assignment temporaries preserve evaluation order.
4. **Recover storage.** Track a proven entry-stack displacement through SP/FP operations. Recover distinct nonoverlapping stack slots; retain explicit memory access when an address or overlapping layout cannot be established. Infer register arguments according to the selected ABI, with uncertainty surfaced.
5. **Analyze data flow.** Solve register liveness over the CFG, materialize live block outputs, simplify constants/casts and substitute single-use values without crossing memory effects. Keep loads/calls/unknown instructions observable.
6. **Structure.** Use dominators and postdominators to identify natural loops and branch joins. Emit if/else and while where reducible regions can be proved; retain labels/gotos for other flow. Do not invent switch cases or indirect targets.
7. **Render with provenance.** Every line records contributing instruction addresses and exact file spans. Structural lines and unsupported statements are distinguished. Provide reverse mapping, coverage, diagnostics, recovered variables, CFG and IR in the exported JSON.
8. **Interact.** Select either code pane to highlight the other. Follow individual instructions to hex patching. Persistent local variable display names, function filtering, raw IR, pseudocode and mapping export support an analyst's workflow.
9. **Patch.** Preview equal-length instruction substitutions, validate bytes and original hash, and export to a new file. Reanalysis of the copy is the next step. Pseudocode text is not compiled back into the original executable.

## Architecture and interfaces

`Engine/decompiler.py` owns architecture-independent expressions, CFG/data flow/structuring, and the original lifters. `Engine/patching.py` provides bounded, explicit instruction rewrites. `worker.py` exposes decompile/patch-preview RPCs; the CLI exposes the same decompiler. Swift models are Codable, the workspace owns cached results and selection, and a dedicated Decompiler view presents synchronized panes and per-instruction patch actions.

Decompilation requests include path, slice, function address, expected SHA-256, and optional variable display names. Results include engine/schema version, function, ABI, lines, variables, blocks, low-level IR, diagnostics, provenance and coverage. Cache identity includes binary hash, slice, function, and user display overrides. Navigation must discard stale asynchronous responses.

## Verification plan

- Semantics-focused unit tests for widths, partial-register writes, signed vs unsigned comparisons, flags, memory barriers, opaque barriers, calls and stack tracking.
- CFG tests for diamonds, early returns, loops, multiple exits and unreachable blocks; verify all targets and instruction-to-line mappings.
- Compile a C corpus with Clang at O0/O1/O2 for ARM64 Mach-O, x64 Mach-O, Linux ELF and Windows COFF. No external binaries are needed. Evaluate the original IR for arithmetic/control-flow functions against independently specified C behavior over boundary/random inputs.
- Verify exact decoder lengths and file bytes, including a multi-byte final x86 instruction, universal slices and relocatable sections.
- Test patch previews, equal-length restrictions, stale hashes, original preservation and reanalysis.
- Run existing regression suite, Swift integration, release build and native UI checks for bidirectional selection and pseudocode-to-offset-to-patch navigation.

## Inspiration and independent implementation

Public descriptions informed the separation of architecture-specific lifting, intermediate representation, transformations, and synchronized views. No Ghidra or Hex-Rays implementation is embedded or copied.

- Ghidra's documented [HighFunction abstraction](https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/HighFunction.html).
- Hex-Rays' documented [microcode representation](https://python.docs.hex-rays.com/ida_hexrays/index.html) and [synchronized microcode view](https://hex-rays.com/blog/spying-on-decompiler-internals-the-hex-rays-microcode-viewer).
- Official [LLVM objdump documentation](https://llvm.org/docs/CommandGuide/llvm-objdump.html).

## Planned boundaries

The first lifters prioritize scalar integer ARM64 and x86/x64. SIMD/floating point, ARM32, complete exception unwinding, jump-table recovery, C++ classes, full type analysis, arbitrary reassembly/relocation and binary rewriting are later work. A supported binary format does not imply every instruction or ABI is supported. Accuracy and traceability take precedence over cosmetic source recovery.

## Implemented release result

The pipeline above is implemented for the stated scalar subset. The shipped native app, CLI, test corpus and verified patch-preview workflow are documented in DECOMPILER_GUIDE.md and DECOMPILER_VERIFICATION.md. Register joins use live canonical block outputs plus local SSA snapshots; full global SSA and memory dependence remain a next stage.

Additional primary semantics references: [Arm AAPCS64](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst), [Intel architecture manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html), and [Apple Mach-O indirect symbol structures](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h).
