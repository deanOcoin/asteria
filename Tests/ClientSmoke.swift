import Foundation
@main struct ClientSmoke {
    static func main() async throws {
        guard let root = ProcessInfo.processInfo.environment["ASTERIA_ROOT"] else { fatalError("Set ASTERIA_ROOT") }
        let path = root + "/Examples/asteria-sample"
        let analysis = try await EngineClient.request(["action": "analyze", "path": path], as: Analysis.self)
        precondition(analysis.instructions.count > 30 && analysis.format == "Mach-O")
        let function = analysis.functions.first { $0.name.contains("score_input") }!
        let decompiled = try await EngineClient.request(["action": "decompile", "path": path, "function": function.address, "sha256": analysis.sha256], as: Decompilation.self)
        precondition(decompiled.coverage.total == decompiled.coverage.mapped && decompiled.coverage.unsupported == 0)
        precondition(decompiled.text.contains("while (true)") && decompiled.text.contains("strlen("))
        let branch = decompiled.instructions.first { $0.mnemonic == "b.hs" }!
        let preview = try await EngineClient.request(["action": "patchPreview", "path": path, "address": branch.address, "kind": "invert", "sha256": analysis.sha256], as: InstructionPatchPreview.self)
        precondition(preview.size == 4 && preview.before != preview.after && preview.replacement.contains("b.lo"))
        let oldProject = Data("{\"version\":1,\"path\":\"sample\",\"sha256\":\"hash\",\"slice\":0,\"annotations\":[]}".utf8)
        let decoded = try JSONDecoder().decode(ProjectFile.self, from: oldProject)
        precondition(decoded.decompilerNames == nil)
        let newProject = ProjectFile(path: path, sha256: analysis.sha256, slice: 0, annotations: [], decompilerNames: ["0:" + function.address: ["x0":"input"]])
        let restored = try JSONDecoder().decode(ProjectFile.self, from: JSONEncoder().encode(newProject))
        precondition(restored.decompilerNames?["0:" + function.address]?["x0"] == "input")
        let debug = DebugClient()
        let target = try await debug.request(["action": "target", "path": path])
        precondition(target.state == "ready")
        let bp = try await debug.request(["action": "breakpoint", "spec": "main"])
        precondition(bp.breakpoints.count == 1 && bp.breakpoints[0].locations > 0)
        let result = try await debug.request(["action": "command", "command": "target list"])
        precondition(result.result.contains("asteria-sample"))
        debug.shutdown()
        print("Swift client smoke PASS: analysis, decompilation + provenance, verified patch preview, backward-compatible projects, LLDB target/breakpoint/console")
    }
}
