import Foundation
import SwiftUI

@main struct WorkspaceSmoke {
    @MainActor static func until(_ ready: () -> Bool) async throws {
        let deadline = Date().addingTimeInterval(20)
        while !ready() { precondition(Date() < deadline, "Timed out waiting for workspace action"); try await Task.sleep(for: .milliseconds(20)) }
    }
    @MainActor static func main() async throws {
        let root = ProcessInfo.processInfo.environment["ASTERIA_ROOT"]!
        let a = try await EngineClient.request(["action": "analyze", "path": root + "/Examples/asteria-sample"], as: Analysis.self)
        let score = a.functions.first { $0.name.contains("score_input") }!, main = a.functions.first { $0.name == "_main" }!
        let w = Workspace(); w.analysis = a; w.page = "Decompiler"
        let previousFollow = UserDefaults.standard.object(forKey: "followCode")
        defer { if let previousFollow { UserDefaults.standard.set(previousFollow, forKey: "followCode") } else { UserDefaults.standard.removeObject(forKey: "followCode") }; w.debugger.shutdown() }
        w.setFollowCode(true); w.selectFunction(score.name, pseudocode: true)
        precondition(w.selectedFunction == score.name)
        w.decompileSelected(); try await until { !w.decompiling }; precondition(w.decompilerError.isEmpty)
        let line = w.decompilation!.lines.first { $0.addresses.count > 1 && $0.kind == "control" }!
        w.selectPseudocode(line); precondition(w.selectedAddress == line.addresses.first && !w.linkedAddresses.isEmpty)
        w.setFollowCode(false)
        let pseudoAddress = w.pseudoAddress, pseudoLine = w.selectedPseudoLine
        w.selectFunction(main.name)
        precondition(w.decompilerFunction?.address == score.address && w.pseudoAddress == pseudoAddress && w.selectedPseudoLine == pseudoLine)
        let instruction = w.selectedInstructions[2]
        w.selectDecompilerAddress(instruction.address)
        precondition(w.pseudoAddress == pseudoAddress && w.selectedPseudoLine == pseudoLine && w.linkedAddresses.isEmpty)
        w.selectPseudocode(line)
        precondition(w.selectedFunction == main.name && w.selectedAddress == instruction.address)
        w.page = "Disassembly"; w.setFollowCode(true)
        precondition(w.decompilerFunction?.address == main.address && w.pseudoAddress == instruction.address)
        w.setFollowCode(false); w.showPseudocode(score.address); w.decompileSelected()
        try await until { !w.decompiling }
        precondition(w.selectedFunction == main.name)
        let variable = w.decompilation!.variables.first { $0.kind == "stack" && !$0.addresses.isEmpty }!
        w.beginRename(RenameTarget(functionAddress: score.address, variable: variable.name))
        try await until { !w.renameBusy }
        let context = w.renameContext!
        precondition(context.selected == variable.name)
        let provenance = w.decompilation!.reverseMap
        w.commitRename(context, variable: variable.name, name: "renamed_score")
        try await until { !w.renameBusy }
        precondition(w.renameError.isEmpty && w.decompilation!.text.contains("renamed_score"))
        precondition(provenance == w.decompilation!.reverseMap && w.selectedFunction == main.name)
        w.beginRename(instruction: instruction.address); try await until { !w.renameBusy }
        precondition(w.renameContext!.function.address == main.address)
        w.renameContext = nil
        w.beginRename(RenameTarget(functionAddress: score.address)); try await until { !w.renameBusy }
        let functionContext = w.renameContext!
        w.commitRename(functionContext, variable: "", name: "return")
        try await until { !w.renameBusy }
        precondition(!w.renameError.isEmpty && w.functions.contains { $0.name == score.name })
        w.commitRename(functionContext, variable: "", name: "calculate_score")
        try await until { !w.renameBusy && !w.decompiling }
        precondition(w.renameError.isEmpty && w.decompilation!.text.contains("calculate_score("))
        precondition(w.selectedFunction == main.name && w.activeFunctionNames[score.address] == "calculate_score")
        let path = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("asteria-workspace-\(UUID()).json")
        defer { try? FileManager.default.removeItem(at: path) }
        w.projectURL = path; w.saveProject()
        let p = try JSONDecoder().decode(ProjectFile.self, from: Data(contentsOf: path))
        precondition(p.followCode == false && p.functionNames?["0"]?[score.address] == "calculate_score")
        precondition(p.decompilerNames?["0:" + score.address]?[variable.name] == "renamed_score")
        w.loadProject(path); try await until { !w.loading }
        precondition(w.error == nil && !w.followCode && w.functions.contains { $0.name == "calculate_score" })
        precondition(w.decompilerNames["0:" + score.address]?[variable.name] == "renamed_score")
        let old = try JSONDecoder().decode(ProjectFile.self, from: Data("{\"version\":1,\"path\":\"x\",\"sha256\":\"y\",\"slice\":0,\"annotations\":[]}".utf8))
        precondition(old.functionNames == nil && old.followCode == nil)
        print("Workspace smoke PASS: independent function/line selections, Follow both directions, explicit jumps, variable/function rename, invalid-name rollback, provenance, saved names, old/new project loading")
    }
}
