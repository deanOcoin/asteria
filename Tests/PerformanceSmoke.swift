import Foundation
import SwiftUI

/// Times the full native client pipeline on a local binary path; the binary is analyzed, never launched.
@main struct PerformanceSmoke {
    @MainActor static func until(_ ready: () -> Bool) async throws {
        let deadline = Date().addingTimeInterval(30)
        while !ready() { precondition(Date() < deadline, "Workspace timed out"); try await Task.sleep(for: .milliseconds(5)) }
    }
    @MainActor static func main() async throws {
        let path = CommandLine.arguments.dropFirst().first ?? ProcessInfo.processInfo.environment["ASTERIA_ROOT"]! + "/Examples/asteria-sample"
        var metrics: [String: Double] = [:]
        let clock = ContinuousClock()
        func seconds(_ start: ContinuousClock.Instant) -> Double {
            let c = (clock.now - start).components
            return Double(c.seconds) + Double(c.attoseconds) / 1e18
        }
        // A heartbeat on the main actor proves that process I/O and JSON decode
        // do not block interaction while a large analysis is in flight.
        var ticks = 0
        let heartbeat = Task { @MainActor in
            while !Task.isCancelled { try? await Task.sleep(for: .milliseconds(20)); ticks += 1 }
        }
        defer { heartbeat.cancel(); EngineClient.shutdown() }
        var start = clock.now
        let a = try await EngineClient.request(["action": "analyze", "path": path], as: Analysis.self)
        metrics["cold_native_analysis_seconds"] = seconds(start)
        precondition(ticks > 0, "Analysis blocked the main actor")
        let w = Workspace()
        start = clock.now; w.analysis = a
        metrics["workspace_index_seconds"] = seconds(start)
        let f = w.function(at: a.entry) ?? a.functions.first!
        start = clock.now
        let result = try await EngineClient.request(["action": "decompile", "path": path, "sha256": a.sha256, "function": f.address], as: Decompilation.self)
        metrics["warm_native_decompile_seconds"] = seconds(start)
        precondition(result.function.address == f.address)
        precondition(!result.reverseMap.isEmpty)
        let previousFollow = UserDefaults.standard.object(forKey: "followCode")
        defer { if let previousFollow { UserDefaults.standard.set(previousFollow, forKey: "followCode") } else { UserDefaults.standard.removeObject(forKey: "followCode") } }
        w.followCode = true; w.page = "Decompiler"; w.selectFunction(f.name, pseudocode: true)
        start = clock.now; w.decompileSelected(); try await until { !w.decompiling }
        metrics["workspace_first_decompile_seconds"] = seconds(start)
        precondition(w.decompilerError.isEmpty)
        start = clock.now
        for _ in 0..<100 { w.decompileSelected() }
        metrics["100_cached_decompile_selections_seconds"] = seconds(start)
        precondition(!w.decompiling && w.decompilation?.text == result.text)
        w.status = "Previous function"
        w.decompileSelected()
        precondition(w.status == "Decompiler · \(result.coverage.mapped)/\(result.coverage.total) instructions mapped · \(result.coverage.unsupported) unsupported")
        start = clock.now
        for ins in result.instructions {
            w.selectDecompilerAddress(ins.address)
            precondition(w.codeIndex.instructionsByAddress[ins.address]?.offset == ins.offset)
            precondition(w.selectedInstructions.count == result.instructions.count)
            precondition(w.selectedPseudocode?.addresses.contains(ins.address) != false)
            _ = w.codeIndex.referencesByAddress[ins.address]; _ = w.linkedAddresses
        }
        metrics["select_all_entry_instructions_seconds"] = seconds(start)
        // The rename sheet should use the already recovered values.
        start = clock.now; w.beginRename(RenameTarget(functionAddress: f.address))
        try await until { !w.renameBusy }
        metrics["cached_rename_picker_seconds"] = seconds(start)
        precondition(w.renameContext?.variables.count == result.variables.count)
        w.renameContext = nil
        // Rapid selection changes settle on the latest function, including cache
        // hits, without an older response overwriting it.
        for next in a.functions.filter({ $0.count < 100 }).prefix(30) {
            w.selectFunction(next.name, pseudocode: true); w.decompileSelected()
        }
        w.selectFunction(f.name, pseudocode: true); w.decompileSelected()
        try await Task.sleep(for: .milliseconds(150))
        precondition(w.decompilation?.function.address == f.address && !w.decompiling)
        // Cancellation of active work must reconnect cleanly and preserve framing.
        let cancelled = Task { try await EngineClient.request(["action": "analyze", "path": path, "refresh": true], as: Analysis.self) }
        try await Task.sleep(for: .milliseconds(10))
        start = clock.now; cancelled.cancel()
        do { _ = try await cancelled.value; preconditionFailure("Cancelled request returned a result") }
        catch is CancellationError { }
        metrics["active_request_cancellation_seconds"] = seconds(start)
        let hexResult = try await EngineClient.request(["action": "hex", "path": path, "offset": 0, "count": 32], as: HexResult.self)
        precondition(hexResult.total == a.size)
        do { let _: Analysis = try await EngineClient.request(["action": "invalid"], as: Analysis.self); preconditionFailure("Expected engine error") }
        catch is EngineError { }
        let recovered = try await EngineClient.request(["action": "hex", "path": path, "offset": 16, "count": 32], as: HexResult.self)
        precondition(recovered.offset == 16)
        print(String(data: try JSONSerialization.data(withJSONObject: metrics, options: [.prettyPrinted, .sortedKeys]), encoding: .utf8)!)
        print("Performance smoke PASS: main-actor responsiveness, indexed selection/provenance, cached decompilation/F2, latest selection wins, cancellation/reconnect, error recovery")
    }
}
