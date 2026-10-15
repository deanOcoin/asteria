# Asteria 0.2 — linked pseudocode

The decompiler is part of the native app. Open `Launch Asteria.command`, open a binary, and choose **Static → Decompiler**. From Disassembly, right-click an instruction and choose **Show linked pseudocode**, use the inspector's **Pseudocode** button, or press **⇧⌘P**.

## From pseudocode to a patch

1. Select a function. The decompiler lifts scalar integer instructions into typed expressions, reconstructs stack storage, simplifies values, and recovers structured control flow.
2. Select a pseudocode line. Every contributing instruction is highlighted in mint in the adjacent disassembly pane. Selecting an instruction performs the reverse lookup and highlights a corresponding line.
3. The disassembly rows show the static virtual address, **FILE offset**, and exact instruction bytes. The Provenance inspector repeats the selected instruction's offset and bytes. A folded expression or branch condition can include several separate instruction spans; never treat them as one contiguous patch range.
4. Select the exact instruction you want to inspect. **Hex / Patch** opens at its whole-file offset, shows the pseudocode navigation context, and prefills its original bytes. Change bytes and save a new copy. **Back to Pseudocode** returns to the linked view.
5. Alternatively choose **Instruction rewrite…**. Preview NOP replacement, inverted conditional branches, unconditional versions of conditional branches, or a supported immediate-field edit. Asteria's own bounded encoders prepare the bytes; LLVM verifies their decoding. **Export patched copy…** writes a separate file with the original hash checked again. **Analyze patched copy** opens fresh analysis.

Pseudocode editing does not compile changes back into the executable. Instruction rewrites preserve the original byte span. They do not allocate new code, relocate instructions, repair signatures/checksums, or guarantee a valid runtime behavior after modification.

## Inspecting and refining code

- **Wrap** makes long expressions readable within the pane. Disable it for horizontal scrolling.
- **Mechanics** shows frame operations, join branches and discarded pure definitions. These instructions remain mapped even when their comments are hidden. Selecting one from disassembly reveals its associated line.
- **Variables** lists inferred arguments, recovered stack slots, temporaries and values carried between blocks. Rename a storage identity with a valid C identifier; **⌘S** saves the names in the existing project format. Old projects remain readable.
- **ABI** chooses automatic detection, AAPCS64, System V x64, Windows x64, or cdecl x86 as appropriate. Calling-convention selection changes the inferred register arguments. Nonstandard calling conventions and complex stack/variadic call arguments remain uncertain.
- **Diagnostics** identifies unsupported semantics and inference limits. `asm_effect(...)`, `unknown_...()` and `indirect_jump(...)` are explicit unresolved effects, not recovered source statements.
- **Lifted IR** shows the low-level operations contributing to the selected line. Export JSON for both original and simplified IR, CFG edges, liveness sets, variables, exact spans, source hash, and the instruction-to-line reverse map.
- **Export → Pseudocode** saves a `.c` text artifact. It is C-like analysis output; helper operations and unrecovered machine state can require a harness or manual work to compile.

## What this implementation recovers

Little-endian ARM64, x86-64 and x86 scalar integer code in the supported Mach-O, PE/COFF and ELF containers. The pipeline includes instruction-width-aware register operations, x86 partial registers, stack slots, scalar loads/stores, integer arithmetic and extensions, comparisons, condition flags, conditional selection, direct and indirect calls, register liveness, local value propagation, dead pure-value removal, dominators/postdominators, natural loops, short-circuit conditions, and if/else regions. Other control flow stays as labels and gotos.

Classic Mach-O indirect symbol tables resolve named import stubs. Known pointer positions in selected C library calls can display extracted strings, and symbol-backed memory addresses can display a global name. Source names and full source types are not reconstructed.

Stack accesses with overlapping widths use explicit memory operations. If a stack address escapes to a call, or unsupported operations invalidate assumptions, stack recovery is disabled for that function rather than assuming separate locals are unaffected.

## Accuracy and scope

This is an original first decompiler release, not Hex-Rays parity. The output has a traceable relationship to instructions, but no claim of general semantic equivalence is made for arbitrary optimized, obfuscated or adversarial code. Coverage counts refer to decoded instructions and supported lifting, not a proof that all binary behavior was recovered.

SIMD/floating point, ARM32 and other CPU lifters, complete indirect/jump-table resolution, global SSA/type recovery, C++/Swift/Objective-C class reconstruction, exceptions, complete library prototypes, multi-register return types and arbitrary relocation-aware reassembly remain future work. x86 cdecl parameter recovery handles scalar stack slots; 64-bit paired returns on 32-bit CPUs are not reconstructed as 64-bit source results. Function boundaries inherit the disassembler's heuristics. Ambiguous overlapping section addresses are rejected by the decompiler.

One function is bounded to 3,000 decoded instructions and 256 basic blocks. The native app retains the 24 most recently used results by binary hash, slice, function and ABI; name edits invalidate cached results. A persistent static worker reuses up to three analyzed images within an instruction budget, checks file content hashes on requests, and invalidates analysis when slices or signature packs change. Reopen an externally changed binary to update the displayed workspace. Cancel stops active work; rapid function changes cancel obsolete requests. All analysis is local and does not execute the opened binary.

## CLI

```sh
./scripts/asteria decompile Examples/asteria-sample --function _score_input
./scripts/asteria decompile /path/to/binary --function 0x100001000 --json --out function.json
./scripts/asteria decompile /path/to/binary --abi win64 --out function-pseudocode.c
```

The CLI can select a function by exact name or start address. Omitting it selects the first discovered function. `--slice` selects a universal slice. Exports use a newly created destination.

## Next development stages

1. Global SSA with memory dependence and escape analysis; stronger variable/type propagation and smaller expressions across basic blocks.
2. Expanded scalar instruction and ABI semantics, reliable prototypes, switch/jump-table recovery, and multi-register returns, driven by additional differential corpora.
3. SIMD/floating-point semantics and language/runtime metadata for Objective-C, Swift and C++.
4. Verified code-cave allocation, relocation-aware assembly, patch transactions and richer before/after decompilation comparisons.

The implementation design and public primary references are in `docs/DECOMPILER.md`. The source is original; neither Ghidra nor Hex-Rays is a dependency.
