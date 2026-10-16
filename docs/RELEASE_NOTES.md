# Asteria 0.3.2 — 16 October 2026

Projects are portable. A saved project stores the binary's path relative to the project file when the two sit in the same folder, and a project whose absolute path no longer exists is tried against a file of the same name beside it. The bundled example projects open on any machine. Comments trimmed across the engine and app; no analysis behaviour changed.

# Asteria 0.3.1 — 8 September 2026

Fixes slow loading and decompilation on large padding regions. Atlas now scans padding in linear time. A persistent static worker reuses content-validated analysis, native JSON decoding runs off the main actor, code navigation uses indexes, and pseudocode uses a bounded LRU cache. Added cancellation for loading and decompilation, including obsolete selections. Signature learning and bulk name application also avoid repeated whole-image scans.

See [performance measurements and verification](PERFORMANCE.md). The recognition criteria, disassembly cap, supported lifters and decompiler complexity limits are unchanged.

# Asteria 0.3 — 8 September 2026

Independent code navigation with a persisted Follow toggle; a shared F2 function/variable rename workflow with stable address and storage identities; original Atlas library recognition with 119 bundled fingerprints, local pack learning/import and collision reporting; and contextual hover help throughout the native interface.

Function overrides propagate to disassembly targets and pseudocode calls without changing call-argument recovery. Names, byte provenance and old projects are covered by regression and native workflow checks. See CODE_WORKFLOW.md and WORKFLOW_VERIFICATION.md for usage, algorithm boundaries and test evidence.

# Asteria 0.2 — 8 September 2026

Added the original linked scalar decompiler, instruction provenance, variable naming, CLI/JSON exports and verified instruction rewrite previews. See [decompiler verification](DECOMPILER_VERIFICATION.md) and [user guide](DECOMPILER_GUIDE.md). The original 0.1 verification record follows.

# Asteria 0.1.0 — verification record

Built on 5 September 2026. Apple Silicon Mac, macOS 26, Xcode 26.6 / Apple Swift 6.3.3, Apple LLVM 21 and LLDB 2100.

## Delivered

- A complete native Mac application in `build/Asteria.app`, plus `Launch Asteria.command`.
- SwiftUI source, isolated Python analysis/debugger engines, CLI, reproducible build/test scripts, original icon source and MIT license.
- Architecture mapped before implementation, README with workflows/shortcuts/support boundaries, and an annotated `Examples/Training.asteria.json` project saved through the app.
- The C training source, executable and matching dSYM are bundled in the app.

## Automated checks passed

**24 Python tests**, including:

- PE32 and PE32+ imports/exports, image-base translation and directory validation.
- ELF32 and ELF64 in little and big endian, section names, load segments and BSS mapping.
- Mach-O 32/64 in both byte orders, symbols/entry and whole-file offsets for universal slices.
- Archive listing, raw/empty inputs, truncated structures, malformed table strides and 320 deterministic mutated inputs.
- String encodings and entropy.
- Overlapping searches and byte wildcards.
- Hex reads; byte comparison including added tails; copy-out patching, original preservation, existing-output rejection, hard-link rejection and stale-hash protection.
- Actual training-binary disassembly, direct calls, symbols and strings.
- PE fixture disassembly and real Clang-generated Windows x86-64 COFF, Linux x86-64 ELF and Linux AArch64 ELF objects.

**Swift client smoke test passed**: decoding real analysis, persistent newline JSON framing, real LLDB target creation, a resolved breakpoint, command response and clean worker shutdown.

**Release build and strict code-signature verification passed.** The app is ad-hoc signed for local use, not notarized for public distribution.

Additional real-file check: `/bin/ls` was recognized as a two-slice universal Mach-O; its x86-64 slice produced 4,061 decoded instructions and 92 symbols. The bundled C training program produces 152 instructions.

## Native app workflows verified

- App launch, training-binary opening, metadata/entropy presentation and control-flow graph rendering.
- Local target preparation and launch, with and without an initial loader stop.
- Symbol breakpoint at `score_input`, and subsequent breakpoint hit.
- Three-frame stack: `score_input → main → start`.
- 164 register values, local variables, selected caller variables (`argc = 1`), and selected-frame LLDB console context.
- Expression evaluation: `atlas_counter = 7`.
- Runtime memory read: 256 bytes at the stopped program counter.
- One-instruction step changed PC by four bytes on AArch64; Step Out returned to `main`.
- Continue to exit status 0; expected output `input=hello-asteria score=42`.
- Relaunch with `hello --wait`, expected score 22 and a running wait loop.
- Pause produced SIGSTOP with a live `__semwait_signal → nanosleep → sleep → main → start` stack.
- Notes editor, applying a label/bookmark/comment, saving an actual `.asteria.json` project, and reopening it in the rebuilt app with the annotation restored. The saved file's hash was checked against the binary.

## Boundaries of verification

- No Windows/Linux remote target was available. The gdb-remote adapter and platform selection are implemented but not claimed as cross-OS end-to-end tested.
- Core loading is implemented through LLDB but no representative core dump was available.
- PID attachment is implemented. The reattach attempt to the short-lived training process reported “no such process”; successful PID attachment is not claimed as verified.
- A detach request completed during the training run, but continued lifetime of the detached process was not established. Detach status means Asteria is no longer monitoring it, not a claim that it remains alive.
- The complete Python launch integration script is provided in `Tests/test_debugger.py`. Local launches inside this session's restricted terminal failed in standalone LLDB as well, so local runtime behavior was verified in the desktop app. Do not misread that terminal restriction as a successful automated launch test.
- Intel hardware, all compiler/language variants, every CPU ABI, malicious-file fuzzing at scale, managed remote VMs and public distribution were not tested.

## Deliberate first-release limits

This release does not include a decompiler, indirect-call recovery, type reconstruction, signature databases, full Objective-C/Swift metadata recovery, PE delay-import/resource browsing, dyld shared-cache loading, automatic unpacking, emulation or record/replay. Mach-O imports/exports derived only from the classic symbol table may be incomplete for stripped binaries using modern dyld fixups/export tries.

Function boundaries and direct-reference graphs are heuristic. Relocatable objects may have overlapping section-relative addresses. File size is limited to 256 MiB; strings, instructions, search hits and graph size are capped with visible notes. The application requires compatible Xcode developer tools at runtime.

## Implementation details worth preserving

The Swift debugger client uses pipe `availableData` for newline framing; a fixed-length read can stall persistent responses. LLDB's asynchronous listener must be drained before reading state. The workbench stores its selected frame and uses `GetFrameAtIndex` plus explicit command execution contexts; Xcode's `GetSelectedFrame` / `SetSelectedFrame` callbacks stalled the standalone worker during testing. Keep these behaviors when extending the debugger.

Optional diagnostic stage logs can be enabled by setting `ASTERIA_DEBUG_TRACE=1` in the worker environment. They are created in the OS temporary directory and capped at 1 MiB per worker; tracing is off by default.
