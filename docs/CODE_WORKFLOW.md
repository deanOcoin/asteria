# Asteria 0.3 — code navigation, names and recognition

The app includes independent code navigation, a shared F2 rename command, automatic Atlas library recognition, and contextual hover help across both workspaces.

## Follow code views

Use **Follow on / Follow off** in either the Disassembly or Decompiler toolbar, or **Analysis → Code Views Follow Each Other**.

With Follow on, selecting a function, instruction or pseudocode line updates the other code view. Mint highlights mark all instructions contributing to the selected pseudocode line; the selected instruction also shows its exact file offset and bytes.

With Follow off, the decompiler keeps its own function and line. The disassembly pane gains its own function picker. You can keep one function's C visible while browsing another function's machine code. Explicit commands such as **Open in Disassembly**, **Show linked pseudocode** and **Select linked instructions** still navigate when you request them.

Turning Follow back on uses the pseudocode selection when you are in the Decompiler, or the disassembly selection when you are in Disassembly. The preference is remembered and included in saved projects.

## Rename from either code view

| Selection | Action |
|---|---|
| Function in either function list | Press **F2**, enter a name, press Return. |
| Function or variable inside pseudocode | Click the individual identifier. Its occurrences highlight; **F2** opens that exact name. |
| Instruction in disassembly | Press **F2**, then choose the function or a recovered value in the Name picker. **↳** marks values linked to that instruction. |
| Instruction context menu | Choose **Rename function / linked variable…**. |
| Decompiler toolbar | The pencil button opens the same rename dialog. |

On keyboards that assign brightness to F2, use **Fn-F2** or the Analysis menu command.

The dialog preserves original function-name evidence and shows a variable's storage identity and machine-width type. Use **Reset name** to remove an override. **Command-S** saves names with the project.

Names must be unique, nonreserved identifiers accepted by the decompiler, up to 80 characters. Invalid names and collisions report an error without committing the edit. Function overrides propagate to function lists, call operands, graph ownership and pseudocode calls. Variable overrides apply to all uses of that recovered value within its function. A machine register may hold several different values over time, so instruction renaming offers correlated values instead of assigning one source variable to the register globally.

Name edits do not alter the executable, instruction bytes, storage identities or instruction-to-pseudocode provenance. Call argument recovery continues to use the original library identity after a display rename.

## Atlas library recognition

Atlas is an original FLIRT-like signature system. It runs automatically after normal symbols and import stubs have been recovered. Open **Library Recognition** to inspect the loaded packs, applied matches, retained symbols and collisions.

The bundled pack contains **119 unique fingerprints** for eight original C reference routines: `memcpy`, `memmove`, `memset`, `memcmp`, `strlen`, `strcmp`, `strncmp` and `strchr`. These were generated from 28 Clang configurations: seven architecture/format targets at O0, O1, O2 and Os, with vectorization and loop unrolling disabled. Source and a compiler/build manifest are included in the project.

This is a starter database for those exact implementations and build families. It is not a general database of Apple's libc, glibc or the Microsoft CRT. Different implementations, compiler versions, instruction selection or optimization settings can prevent matches. Atlas does not load IDA's proprietary `.sig` files.

To extend recognition:

1. Open a known library or linked binary with useful symbol names, or give its functions analyst names with F2.
2. Choose **Library Recognition → Learn / export…** to save an `.atlas.json` pack.
3. Choose **Import pack…**. Asteria validates and installs it locally, then rescans the current file.
4. Open a stripped build with matching machine code. Unique matching functions receive names automatically.

For a ready demonstration, open `Examples/atlas-recognition-sample` and visit Library Recognition: all eight reference routines are recovered from the stripped file. `Examples/Workflow-Training.asteria.json` opens the standard training binary with `calculate_score` and `score` already named and Follow off.

Installed packs live in `~/Library/Application Support/Asteria/Signatures`. **Rescan** reloads them. Reimporting identical content is idempotent. Malformed packs are reported without disabling the rest of analysis.

CLI equivalents, from the Asteria project folder:

```sh
scripts/asteria signature-learn /path/to/named-binary --library "My runtime" --out /path/to/runtime.atlas.json
scripts/asteria signature-import /path/to/runtime.atlas.json
scripts/asteria analyze /path/to/stripped-binary --out /path/to/analysis.json
```

## How a signature is checked

Atlas indexes candidate signatures by architecture, bit width, byte order and initial instruction descriptor. It checks the entire learned body, keeping every ordinary instruction's bytes and decoded operands. Direct branches use instruction-relative target indexes; external direct code references require matching names. Internal branch structure and instruction widths therefore survive rebasing without turning arbitrary immediates or data addresses into wildcards.

Signatures require at least four instructions and 16 bytes. Matching only starts at discovered entries or plausible boundaries after returns and alignment. It does not consume another discovered function entry. Missing bytes, unresolved external code references and overlapping section-relative addresses cause matching or learning to decline. Different candidate names for the same fingerprint are listed as ambiguous and are not assigned automatically. Existing symbol and analyst names take precedence.

Function-boundary discovery remains heuristic. A match identifies a code fingerprint; it does not establish who published a binary or whether the binary is trustworthy.

## Contextual help

Hover over navigation items, controls, table data, code addresses, offsets, names, patch actions, debugger launch fields, stepping controls, breakpoint data, registers, variables, modules and memory settings. More than 200 tooltip attachment points now cover the interface. Previous tooltips remain.

Help explains distinctions such as static VA versus file offset versus runtime address, what each command changes, and why some analysis results are uncertain.

## Project compatibility

The project schema remains version 1. New optional fields store `functionNames`, `decompilerNames` and `followCode`; old projects still open. Function names are scoped by slice and function start address. Variable names are scoped by slice, function address and stable recovered-storage identifier. The saved SHA-256 still protects against applying a project to a different binary.

## Public references

The design takes conceptual inspiration from the documented use of library signatures and collision handling in [Hex-Rays FLIRT](https://docs.hex-rays.com/user-guide/signatures/flirt) and its [signature generation workflow](https://docs.hex-rays.com/user-guide/signatures/flirt/generate-flirt-signature-file). Decoding uses the documented [LLVM objdump](https://llvm.org/docs/CommandGuide/llvm-objdump.html) interface. Atlas's matcher, schema and bundled reference implementations are original Asteria code; no proprietary signature database is included.
