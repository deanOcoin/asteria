# Asteria — architecture and delivery map

Initial plan · 5 September 2026 · Decompiler update · 8 September 2026

## Product

A native macOS reverse engineering workbench with distinct Static and Dynamic workspaces. The first release must perform useful real analysis, persist analyst work, and control LLDB. It is an extensible foundation, not a claim of parity with IDA's decades of analysis and decompiler development.

## User workflow

1. Open a binary without executing it. Identify format, architecture, slices, entry point, sections, symbols, dependencies, hashes, and security metadata.
2. Navigate from functions, strings, imports, or an address to disassembly and bytes. Inspect direct branch cross-references and a function's control-flow graph.
3. Search content, annotate addresses, bookmark findings, compare files, export a report, and produce a separately saved patched copy.
4. Switch to Dynamic. Create a target, choose local launch, PID attach, remote gdb connection, or a core file. Execution requires an explicit debugger action.
5. Set breakpoints, step instructions/source, continue/pause, inspect threads, frames, registers, variables, modules, memory, and process output. Use a full LLDB console for advanced commands.

## Release implementation map

| Area | First working release | Expansion path |
|---|---|---|
| Desktop | SwiftUI/AppKit app, dark analysis layout, keyboard shortcuts, file picker/drop, recent files | Multi-document windows and workspace layouts |
| Formats | PE32/PE32+; COFF objects; Mach-O 32/64; universal slices; ELF32/64 little/big endian; archive listing; raw bytes | dyld shared cache, firmware containers, resource trees |
| CPU support | LLVM-supported ARM/Thumb/AArch64 and x86/x86-64 on this Xcode | Optional upstream LLVM for RISC-V/MIPS/PowerPC |
| Metadata | Headers, sections/segments, VA/file mapping, entry, libraries, symbols/imports/exports, SHA-256/MD5, entropy, format flags | Full Objective-C/Swift type reconstruction and DWARF type browser |
| Code | LLVM disassembly, function labels and direct-call discovery, address jump, direct branch references, basic blocks and CFG | Recursive analysis, indirect branch recovery, function signatures |
| Data | ASCII/UTF-16 strings, file/VA hex viewer, wildcard byte search, byte comparison, copy-out patching | Structure editor and relocation-aware patch assembler |
| Analyst work | Per-binary project JSON with hash identity, comments, labels/bookmarks, report export | SQLite multi-user history and plugin API |
| Dynamic | LLDB Python API, asynchronous process state; local launch/attach; remote gdb stub connection; core loading | Managed VM workflows, platform file sync, record/replay |
| Debug controls | Symbol/address/conditional breakpoints, enable/delete, run/continue/pause/step/finish, detach/terminate | Tracepoint editor, event automation |
| Debug inspectors | Threads/frames selection, registers, local variables, modules, memory reads, expression evaluation, console | Timeline, automatic watch snapshots, richer visualization |
| Decompilation | Original scalar ARM64/x64/x86 lifters, typed IR, local value optimization, CFG structuring, stack variables, linked provenance, copy-out instruction rewrites | Global SSA/memory analysis, stronger types/prototypes, jump tables, SIMD/FP; see DECOMPILER.md |

## Support contract

- Static opening never launches the sample. Unknown data receives a raw-byte view. Recognized malformed files return a useful parse error rather than silently becoming a valid executable.
- Mach-O executables, dylibs, bundles and objects share the Mach-O loader. Universal binaries allow explicit slice selection.
- PE executables, DLLs and drivers share the PE loader. COFF objects use the COFF loader. ELF executables, shared libraries, objects and core containers share the ELF loader.
- x86 and ARM family decoding depends on the installed LLVM. Other architectures retain metadata/hex/strings when the installed decoder lacks support.
- Linux and Windows execution needs a matching remote OS/stub. Asteria does not emulate an OS. The remote transport is implemented; end-to-end cross-OS testing requires an actual remote machine.
- Local attach and launch remain subject to macOS debugger authorization, code signing, architecture support, and SIP. Protected processes are not bypassed.
- Direct references and CFGs are conservative, heuristic results. Indirect destinations and stripped function boundaries can remain unknown.

## Component design

```text
SwiftUI app
 ├── Workspace model: document, navigation, async loading, saved analyst notes
 ├── Static: Overview / Code / Decompiler / Graph / Sections / Symbols / Imports / Strings / Hex / Search / Compare / Notes
 ├── Dynamic: Session / Breakpoints / Threads & stack / Registers / Variables / Modules / Memory / Console
 ├── Static worker process → Python standard-library loaders → LLVM tools
 └── Debug worker process ↔ newline JSON RPC ↔ LLDB Python SB API ↔ debugserver / remote gdb stub
```

The Python engine is kept outside the UI process. Each static request runs in an isolated subprocess with bounded input/output and tool timeouts. Debugging uses one serialized worker with asynchronous LLDB execution so Pause remains reachable while the target runs. The UI polls state and never blocks the main thread on analysis. Paths and arguments use structured process arguments, not shell interpolation.

## Core data model

An analysis includes file identity, format/architecture, slices, headers, memory regions, sections, symbols, dependencies, strings, instructions, discovered functions, direct references, entropy bins, and warnings. Addresses are unsigned integers serialized as hex strings at UI boundaries to avoid precision loss. File offsets remain distinct from virtual and runtime addresses. Fat slices preserve absolute file offsets. Runtime PCs are LLDB load addresses; the UI labels them separately from static VAs.

Projects store schema version, binary path/hash, selected slice, analyst annotations and optional decompiler variable names. Patches always require an explicit output path; the engine refuses overwriting the input or a hard link to it. Reports identify truncation, analysis limitations and the original hash.

## Robustness and limits

Validate every structural read, integer range, table count, and string boundary. Reject oversized declared tables. Bound files to 256 MiB for this release, strings to 30,000, disassembly to 120,000 instructions, search hits to 10,000, and external tool output to 32 MiB. Surface limits to the analyst. Do not auto-load target Python scripts, execute .lldbinit, download symbols, or evaluate expressions during static analysis.

## Build and distribution

Swift package targeting macOS 14+, no network package dependencies. Bundle the Python engine into Asteria.app. Discover Xcode/Command Line Tools via xcrun. Use the matching developer Python for LLDB ABI compatibility. Build script creates and ad-hoc signs the app, copies the training sample, and provides a double-click launcher. Xcode or compatible Command Line Tools with LLVM/LLDB/Python remain runtime requirements; App Store distribution and notarization are later work.

## Validation gates

1. Unit fixtures for PE32/PE32+, ELF32/64 and endianness, Mach-O and universal slices, COFF, archive and raw data.
2. Malformed/truncated input and randomized parser robustness; correct offset/VA mapping; BSS handling; bounded counts.
3. Compile a harmless local C training binary, analyze actual machine code, verify symbols, strings, direct calls and CFG edges.
4. Verify search, diff, copy-out patching and unchanged source hash.
5. Build and launch the app; inspect actual UI, open the training binary, navigate static views.
6. LLDB integration: target, breakpoint, launch, stop, register/frame/memory inspection, stepping, continue, exit. Report environment permission failures honestly.
7. Record implemented features, tested paths and remaining limitations in RELEASE_NOTES.md.

## Primary references

- [Microsoft PE/COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [ELF ABI](https://refspecs.linuxfoundation.org/elf/gabi4+/contents.html)
- [Apple Mach-O structures](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
- [LLVM objdump](https://llvm.org/docs/CommandGuide/llvm-objdump.html)
- [LLDB Python API](https://lldb.llvm.org/python_api.html)
- [LLDB remote debugging](https://lldb.llvm.org/use/remote.html)
