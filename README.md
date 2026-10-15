# Asteria

A native Mac workbench for taking compiled programs apart: static analysis of
Mach-O, PE, COFF and ELF files, an original decompiler whose pseudocode stays
linked to the exact instructions and bytes behind it, library recognition, and
live debugging through LLDB. SwiftUI on the front, a Python engine behind it,
LLVM for decoding. No third-party packages, no network, nothing leaves the
machine.

## Build and run

Requirements: macOS 14 or newer with Xcode (or the Command Line Tools) for
Swift, Clang, LLVM objdump, LLDB and its Python. Built and tested on Apple
Silicon with macOS 26 and Xcode 26.6; Intel is untested. The build uses the
host architecture.

```sh
./scripts/build.sh                 # optimised, ad-hoc signed build/Asteria.app
open "Launch Asteria.command"      # builds on first run, then opens the app
./scripts/test.sh                  # parser, decompiler, recognition and session tests
./scripts/test.sh --debugger       # real LLDB launch tests; needs debugger access
```

Choose **Explore training binary** on the welcome screen to start with the
bundled sample. The app is ad-hoc signed for local use, not notarised.

## Static analysis

- Mach-O 32/64, universal/fat slices, PE32/PE32+, COFF objects, ELF32/64 in both byte orders; archive member listing and raw files.
- Metadata, entry point, image base, section/segment permissions, libraries, symbols, imports/exports, SHA-256, MD5, entropy plot and format flags.
- ARM/AArch64 and x86/x86-64 disassembly through the installed LLVM. Function list, address navigation, direct branch/call cross-references, basic blocks and zoomable control-flow graphs.
- ASCII, UTF-16LE and UTF-16BE strings; byte viewer; overlapping text and wildcard byte searches.
- Byte comparison, copy-out patching with source hash validation, labels, comments, bookmarks, saved analysis projects, Markdown reports and full analysis JSON export.

## Original linked decompiler

**Static → Decompiler** (⇧⌘P) pairs C-like pseudocode with disassembly and exact file offsets. Select either pane to trace contributing instructions. Recover integer expressions, stack variables, branches and loops; rename variables, inspect lifted IR, and export pseudocode with bidirectional provenance. Instruction rewrites preview equal-size replacements and verify them with LLVM before exporting a patched copy.

See the [decompiler user guide](docs/DECOMPILER_GUIDE.md), [design](docs/DECOMPILER.md), and [verification](docs/DECOMPILER_VERIFICATION.md) for supported semantics and boundaries.

## Dynamic analysis

- Real LLDB process control, with an independent Dynamic workspace.
- Local Mac launch, arguments, environment overrides, working directory, stop at entry, PID attach, gdb-remote connections and core loading.
- Symbol/address/conditional breakpoints, hit counts, enable/disable and delete.
- Continue, pause, instruction/source stepping, finish frame, detach and terminate.
- Thread and frame selection, registers, local variables, modules, runtime memory, explicit expressions, process output and stdin.
- Full LLDB console for watchpoints, register/memory writes, detailed image queries and advanced debugger commands.

## Quick tour

1. Open the training binary. In **Static → Disassembly**, select `_score_input` in Functions. Click an instruction to see its address, bytes and direct references.
2. **Control Flow** shows the function's blocks. Use the zoom slider and scroll. Double-click a block to return to its instructions.
3. **Strings** filters ASCII and UTF-16 content. Right-click a string to copy it or inspect its bytes. Use **Search** for `41 ?? 41` or a text pattern across the whole file.
4. Click **Dynamic**, select **Local macOS**, then **Prepare target**. Under **Breakpoints**, add `score_input`.
5. Return to **Session**, leave **Stop at entry** checked and **Launch locally**. The first stop may be in the dynamic loader. Press **Continue** to reach `score_input`.
6. Inspect **Threads & Stack**, **Registers**, **Variables** and **Memory**. Memory uses runtime addresses, which may differ from static addresses because of ASLR.
7. Step with Over / Into / Out. Continue to normal exit. Add `hello --wait` as launch arguments for a 30-second pause/continue exercise.
8. In Static, use **Notes** to apply a label, comment or bookmark to an address. **⌘S** saves the `.asteria.json` project. Use **File → Open Project** to restore it.

## Format and platform support

| Input | Static inspection | Local execution | Remote debugging |
|---|---|---|---|
| Mach-O executable / dylib / bundle / object | Yes, including universal slice selection | Executables supported by the host OS/CPU; a dylib alone is not a process | Compatible LLDB/debugserver target |
| PE executable / DLL / driver | Headers, imports/exports, sections, code and data | Requires Windows; macOS cannot launch it | Compatible Windows gdb-remote stub, subject to LLDB/target support |
| COFF object | Sections, symbols, code and data | Link into an executable first | Analyze local symbols for a remote process |
| ELF executable / shared library / object / core container | 32/64-bit, little/big endian metadata; code where LLVM supports the architecture | Requires the appropriate target OS | Linux lldb-server or compatible gdb stub |
| Archive | Member names, offsets, sizes, bytes and strings | Not applicable | Extract a member first |
| Raw / unknown | Bytes, hashes, entropy, strings, search, comparison, patches | No assumed architecture or execution | Requires a separately prepared debugger target |

Apple's bundled LLVM here provides ARM and x86 family decoders. Other architectures retain format metadata, hex and strings but may have no disassembly. Relocatable objects can reuse addresses between sections; cross-section navigation is ambiguous.

## Remote debugging

Prepare a local copy of the target binary in Static, choose the matching remote platform in Dynamic, then **Prepare target**. On a Linux target with `lldb-server`:

```sh
lldb-server gdbserver 127.0.0.1:1234 ./sample
```

Forward the port from the Mac:

```sh
ssh -L 1234:127.0.0.1:1234 user@target
```

Connect to `localhost:1234` in Asteria. This is a gdb-remote stub connection, not an LLDB platform-server endpoint. Remote server setup, OS/architecture compatibility and symbol matching are the user's environment responsibilities. The transport is implemented; no Windows/Linux remote host was available for cross-OS end-to-end testing. Use the LLDB console for platform-specific setup beyond this connection flow.

## Address conventions

- **Static VA:** the preferred address encoded in the binary, such as PE image base + RVA.
- **File offset:** the byte position in the original file. Universal slice offsets remain relative to the entire file.
- **Runtime address:** the load address reported by LLDB after ASLR and module loading.
- Jump-to-VA and static address breakpoints accept hexadecimal. Memory reads should use `0x`-prefixed runtime addresses. BSS/virtual-only tails are not mapped to unrelated file bytes.

## Projects, reports and patches

Projects store the binary path, SHA-256, selected slice, analyst annotations and decompiler variable display names. A hash mismatch stops restoration. Projects do not embed the original binary or a full analysis cache, so keep the original available. When the binary sits next to the project file the path is saved relative to it, so the two can be moved together; a project whose absolute path no longer exists is also tried against a file of the same name beside it.

**Hex & Patch** replaces bytes at the displayed file offset and saves a separate, newly named output. Existing files, the source, and hard links to the source cannot be overwritten by the patch engine. Code signatures and checksums are not repaired. Reopen the patched copy for fresh analysis.

Markdown reports contain identity, metadata, dependencies, sections, notes and limitations. Full JSON exports include the complete bounded analysis tables. Use the saved project to export analyst annotations in machine-readable form.

## Testing notes

`./scripts/build.sh debug` produces a debug build. Swift client protocol smoke test:

```sh
mkdir -p .cache/swift
xcrun swiftc -module-cache-path .cache/swift \
  Sources/Asteria/Models.swift Sources/Asteria/EngineClient.swift \
  Tests/ClientSmoke.swift -o .cache/client-smoke
ASTERIA_ROOT="$PWD" .cache/client-smoke
```

Debugger tests may fail inside restricted execution sandboxes even when the app works normally. A standalone LLDB test provides a useful comparison. macOS SIP, protected/hardened targets, authorization and CPU compatibility can independently prevent launching or attaching. Asteria does not bypass those restrictions.

Quit Asteria before rebuilding the app bundle in place, and relaunch the completed build before testing native file dialogs. The app bundles its engine and sample; Xcode and LLDB remain runtime dependencies.

## Command-line analysis

```sh
./scripts/asteria analyze /path/to/binary --out analysis.json
./scripts/asteria decompile /path/to/binary --function 0x100001000 --json --out function.json
./scripts/asteria hex /path/to/binary --offset 0x200 --count 512
./scripts/asteria search /path/to/binary '48 8B ??' --mode hex
./scripts/asteria compare /path/to/original /path/to/modified
./scripts/asteria patch /path/to/original /path/to/new-copy 0x200 '90 90'
```

## Keyboard shortcuts

| Shortcut | Action |
|---|---|
| ⌘O / ⇧⌘O | Open binary / open project |
| ⌘S | Save analyst project |
| ⌘1 / ⌘2 | Static / Dynamic workspace |
| ⌘D / ⇧⌘G | Disassembly / control-flow graph |
| ⇧⌘P | Linked pseudocode |
| F5 / F6 / F7 / F8 | Continue / instruction over / instruction into / finish frame |

Function keys may require `fn` depending on macOS keyboard settings.

## Limits

The decompiler is an original scalar one and does not claim parity with IDA Pro or Hex-Rays. Full source-type reconstruction, signature databases, emulation, automatic unpacking, indirect branch recovery, managed VMs and record/replay remain future work. Graphs and function boundaries are heuristic. Imports may be incomplete for stripped Mach-O files whose bindings exist only in chained fixups/export tries. PE delay imports, resources, relocation application, and full DWARF/PDB type browsing are not implemented.

Files are capped at 256 MiB, extracted strings at 30,000 (individual strings displayed up to 4 KiB), disassembly at 120,000 instructions, searches at 10,000 hits and tool output at 32 MiB. The graph shows at most 4,000 instructions / 128 blocks. Large files are memory-resident; paging and cancellation are future improvements. No automatic sample execution, target script loading, cloud upload, telemetry or symbol download is part of static opening.

## Documentation

- [Architecture](docs/ARCHITECTURE.md), with the primary format and API references
- [Decompiler design](docs/DECOMPILER.md), [user guide](docs/DECOMPILER_GUIDE.md) and [verification](docs/DECOMPILER_VERIFICATION.md)
- [Code navigation, renaming and Atlas recognition](docs/CODE_WORKFLOW.md) and its [verification](docs/WORKFLOW_VERIFICATION.md)
- [Performance measurements](docs/PERFORMANCE.md)
- [Release notes](docs/RELEASE_NOTES.md)

## Licence

MIT.
