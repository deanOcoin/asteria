# Asteria 0.3.1 performance verification

Verified on 8 September 2026 on the development Apple Silicon Mac, using the user's local `CrackMeTestPE.exe` (1.2 MB). Static inspection only; the PE was neither executed nor patched.

## Measurements

| Operation | Before | After |
| --- | ---: | ---: |
| Cold engine analysis, including Atlas | 56.09 s | 2.61 s median (2.59–2.65 s, three runs) |
| Native analysis request, including worker startup, transfer and Swift JSON decoding | Not separately recorded | 3.66–3.70 s |
| Build native navigation indexes | Not separately recorded | 41–52 ms |
| Entry-function decompilation after opening, engine including content validation | Repeated the approximately 56 s analysis before lifting | 15 ms |
| Entry-function decompilation after opening, native request | Not separately recorded | 27–30 ms |
| First workspace pseudocode selection, including 75 ms navigation debounce | Not separately recorded | 100 ms |
| Return to cached pseudocode | Not separately recorded | 1.12 ms average over 100 selections |
| Cached F2 rename dialog preparation | Not separately recorded | 9–10 ms |
| Cancel active native analysis request | Not available | 7–8 ms |

The engine load improvement is approximately **21.5×**. These are measurements on one Apple Silicon Mac and one binary, not promises for arbitrary files. The native request measurement excludes final SwiftUI layout; the rebuilt application's overview, entry pseudocode, larger function and F2 dialog were separately verified through native interaction and a screenshot.

All 467 discovered function regions were attempted against the loaded analysis. 458 returned pseudocode; nine reported the existing instruction-count or control-flow complexity limits. Median engine time per region was 10 ms and the slowest was 233 ms. A returned result can contain explicitly marked unsupported effects; completion is not a claim of full semantic recovery.

The existing 120,000-instruction disassembly cap and the 3,000-instruction / 256-block decompiler limits remain. Full analysis output, including instruction bytes, offsets, function discovery, references, warnings and recognition, exactly matched the baseline. Entry pseudocode and provenance also matched exactly. The decompiler's generated-code version remains 0.3.0 because its semantics did not change; the application version is 0.3.1.

## Causes and changes

The baseline profile attributed 63.55 of 66.86 profiled seconds to Atlas recognition. For every padding instruction, it walked backward to find the preceding non-padding instruction. Long INT3/NOP runs therefore caused quadratic work. A forward scan now retains that preceding instruction, preserving the same candidate boundaries and matching criteria. Recognition boundary reconstruction, signature learning, and bulk name application also use indexes or single passes.

Previously each pseudocode or rename request started a fresh Python process and repeated full-file analysis. The native app now owns a persistent static worker, separate from LLDB. It caches at most three analyzed images, evicting least-recently-used images when their total exceeds 180,000 instructions (one large image may remain). It hashes file contents on each request and keys reuse by resolved path, slice, hash and signature-pack identity. Analyst names are isolated overlays. Pack changes, edits, changed slices and explicit recognition rescans invalidate reuse. No analysis cache is written to disk.

Native response decoding now reads a typed JSON envelope directly on the worker queue. It avoids the former JSON-to-dictionary-to-JSON-to-model round trip and scans each received byte for framing only once. Navigation uses indexes for function instructions, instruction addresses, references, names and pseudocode provenance. Syntax and identifier patterns are compiled once. Pseudocode retains the 24 most recently used function/ABI results instead of clearing every result at the cache limit.

Cancel is available while loading or decompiling. Rapid function changes debounce for 75 ms and cancel obsolete work. Cancellation interrupts the owning worker transaction, skips pending cancelled requests and reconnects for the next request. Completed engine errors retain a usable cache. Reopen an externally edited binary to update the displayed workspace; cached on-screen pseudocode belongs to the currently loaded analysis.

## Checks completed

- 106 automated tests pass: 24 engine, 45 decompiler, 22 recognition/naming, and 15 new session/performance regressions.
- The decompiler suite includes 9,813 differential rendered-C executions across 183 functions from 21 target/optimization configurations.
- The new padding regression counts instruction accesses rather than relying on fragile wall-clock thresholds.
- Session checks cover analysis reuse, same-size edits with restored modification times, deletion, hash mismatch, slices, signature identity changes, explicit rescans, eviction, name overlay isolation, name swaps, invalid-name recovery, persistent request framing and patch-preview verification.
- Swift client smoke passes for analysis, decompilation/provenance, verified patch preview, projects and LLDB target/breakpoint/console operations.
- Swift workspace smoke passes for independent selections, Follow in both directions, explicit jumps, variable/function rename, invalid-name rollback, provenance, saved names and old/new projects.
- Swift performance smoke passes on the reported PE for main-actor responsiveness during loading, indexed selection/provenance, cached results and F2, latest-selection wins, accurate cache-hit status, active cancellation, reconnect and error recovery.
- The release app builds without compiler warnings and passes strict deep code-signature verification. Native interaction confirmed version 0.3.1, successful loading of the PE, entry pseudocode, the slowest tested function's pseudocode and the cached F2 dialog.

## Reproduce

Run from the Asteria project folder:

```sh
scripts/test.sh
xcrun swiftc -O -module-cache-path .cache/swift \
  Sources/Asteria/Models.swift Sources/Asteria/EngineClient.swift \
  Sources/Asteria/Workspace.swift Tests/PerformanceSmoke.swift \
  -o .cache/performance-smoke
ASTERIA_ROOT="$PWD" .cache/performance-smoke /path/to/binary
```

Local baseline profiles, output parity snapshots and timing logs are under `work/performance`. These local snapshots include the analyzed binary's metadata and code. They are not bundled into the application.
