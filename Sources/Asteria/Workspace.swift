import AppKit
import SwiftUI
import UniformTypeIdentifiers

@MainActor final class Workspace: ObservableObject {
    @Published var analysis: Analysis? {
        didSet { codeIndex = AnalysisIndex(analysis); codeNames = CodeNameIndex(functions: functions, result: decompilation) }
    }
    private(set) var codeIndex = AnalysisIndex()
    private(set) var codeNames = CodeNameIndex()
    private var pseudoLines: [Int: PseudocodeLine] = [:]
    private var pseudoAddresses: Set<String> = []
    private var analysisTask: Task<Void, Never>?
    private var decompileTask: Task<Void, Never>?
    private var decompilerOrder: [String] = []
    @Published var loading = false
    @Published var error: String?
    @Published var status = "Ready"
    @Published var mode = "Static"
    @Published var page = "Overview"
    @Published var filter = ""
    @Published var selectedAddress = ""
    @Published var pseudoFunctionAddress = ""
    @Published var pseudoAddress = ""
    @Published var followCode = UserDefaults.standard.object(forKey: "followCode") as? Bool ?? true
    @Published var functionNames: [String: [String: String]] = [:]
    @Published var renameTarget: RenameTarget?
    @Published var renameContext: RenameContext?
    @Published var renameBusy = false
    @Published var renameError = ""
    @Published var decompilation: Decompilation? {
        didSet {
            pseudoLines = Dictionary(uniqueKeysWithValues: (decompilation?.lines ?? []).map { ($0.id, $0) })
            pseudoAddresses = Set(selectedPseudocode?.addresses ?? [])
            codeNames = CodeNameIndex(functions: functions, result: decompilation)
        }
    }
    @Published var decompiling = false
    @Published var decompilerError = ""
    @Published var decompilerABI = "auto"
    @Published var selectedPseudoLine: Int? { didSet { pseudoAddresses = Set(selectedPseudocode?.addresses ?? []) } }
    @Published var decompilerNames: [String: [String: String]] = [:]
    @Published var hexContext = ""
    @Published var hexSelectionBytes = ""
    private var decompilerToken = UUID()
    private var decompilerCache: [String: Decompilation] = [:]
    @Published var hexOffset = 0
    @Published var memoryAddress = ""
    @Published var debugTargetPath = ""
    @Published var debugTargetPlatform = "host"
    @Published var launchPlatform = "host"
    @Published var launchArguments = ""
    @Published var launchDirectory = ""
    @Published var launchEnvironment = ""
    @Published var stopAtEntry = true
    @Published var attachPID = ""
    @Published var remoteEndpoint = "localhost:1234"
    @Published var selectedFunction = ""
    @Published var annotations: [Annotation] = []
    @Published var projectURL: URL?
    @Published var dirty = false
    @Published var debug = DebugSnapshot.empty
    @Published var debugBusy = false
    @Published var debugStarted = false
    @Published var console = ""
    @Published var recent: [String] = UserDefaults.standard.stringArray(forKey: "recent") ?? []
    let debugger = DebugClient()
    private var generation = UUID()
    private var pollTask: Task<Void, Never>?
    private var pollingBusy = false
    var functions: [BinaryFunction] { analysis?.functions ?? [] }
    var selectedInstructions: [Instruction] {
        guard let a = analysis else { return [] }
        return selectedFunction.isEmpty ? a.instructions : codeIndex.instructionsByFunction[selectedFunction] ?? []
    }
    func openPanel(project: Bool = false) {
        let panel = NSOpenPanel(); panel.canChooseDirectories = false; panel.allowsMultipleSelection = false
        panel.message = project ? "Open an Asteria project (.asteria.json)" : "Choose a binary. Static opening does not execute it."
        if panel.runModal() == .OK, let url = panel.url {
            if project || url.lastPathComponent.hasSuffix(".asteria.json") { loadProject(url) }
            else { open(url) }
        }
    }
    func allowReplace() -> Bool {
        guard dirty else { return true }
        let alert = NSAlert(); alert.messageText = "Save analysis project before opening another file?"; alert.informativeText = "Unsaved function and variable names, labels, bookmarks and comments belong to the current binary."
        alert.addButton(withTitle: "Save"); alert.addButton(withTitle: "Discard"); alert.addButton(withTitle: "Cancel")
        let result = alert.runModal()
        if result == .alertFirstButtonReturn { saveProject(); return !dirty }
        return result == .alertSecondButtonReturn
    }
    func open(_ url: URL, slice: Int = 0, restored: ProjectFile? = nil, project: URL? = nil, preserve: Bool = false) {
        if !preserve && !allowReplace() { return }
        analysisTask?.cancel(); decompileTask?.cancel()
        let token = UUID(); generation = token; decompilerToken = UUID()
        loading = true; decompiling = false; error = nil; status = "Analyzing \(url.lastPathComponent)…"
        analysisTask = Task {
            do {
                let restoredNames = preserve ? functionNames : (restored?.functionNames ?? [:])
                let a = try await EngineClient.request(["action": "analyze", "path": url.path, "slice": slice, "functionNames": restoredNames[String(slice)] ?? [:]], as: Analysis.self)
                guard generation == token else { return }
                if let restored, restored.sha256 != a.sha256 { throw EngineError(message: "The binary hash differs from the saved project. Open the binary directly to analyze its current contents.") }
                analysis = a
                decompilerToken = UUID(); decompilation = nil; decompiling = false; decompilerError = ""; selectedPseudoLine = nil; clearDecompilerCache(); hexContext = ""; hexSelectionBytes = ""
                if !preserve { decompilerNames = restored?.decompilerNames ?? [:] }
                if !preserve { functionNames = restoredNames; followCode = restored?.followCode ?? followCode }
                if !preserve { annotations = restored?.annotations ?? []; dirty = false; projectURL = project }
                selectedAddress = a.entry; selectedFunction = ""; page = "Overview"; filter = ""; mode = "Static"
                pseudoAddress = a.entry; pseudoFunctionAddress = ""; renameTarget = nil; renameContext = nil
                recent.removeAll { $0 == url.path }; recent.insert(url.path, at: 0); recent = Array(recent.prefix(8)); UserDefaults.standard.set(recent, forKey: "recent")
                status = "\(a.format) · \(a.arch) · \(a.instructions.count.formatted()) instructions"
            } catch is CancellationError { }
            catch { if generation == token { self.error = error.localizedDescription; status = "Analysis failed" } }
            if generation == token { loading = false }
        }
    }
    func cancelAnalysis() {
        analysisTask?.cancel(); generation = UUID(); loading = false; decompiling = false
        status = "Analysis cancelled"
    }
    func openSample() {
        let candidates = [try? EngineClient.root().appendingPathComponent("Examples/asteria-sample"), Bundle.main.resourceURL?.appendingPathComponent("asteria-sample")].compactMap { $0 }
        if let url = candidates.first(where: { FileManager.default.fileExists(atPath: $0.path) }) { open(url) }
        else { error = "Training binary not found. Run scripts/build.sh." }
    }
    func navigate(_ address: String, code: Bool = true) {
        selectedAddress = address
        if code, let v = addressValue(address), let a = analysis {
            if let exact = codeIndex.instructionsByAddress["0x" + String(v, radix: 16)] { selectedFunction = exact.function }
            else if let f = a.functions.last(where: { (addressValue($0.address) ?? 0) <= v && (addressValue($0.end) ?? 0) >= v }) { selectedFunction = f.name }
            else { selectedFunction = "" }
            page = "Disassembly"
            renameTarget = nil
            if followCode { syncPseudocode(to: address) }
        } else { page = "Hex & Patch" }
    }
    func showBytes(_ offset: Int, context: String = "", bytes: String = "") { hexOffset = max(0, offset); hexContext = context; hexSelectionBytes = bytes; page = "Hex & Patch" }
    func label(_ address: String) -> String { annotations.first { $0.address == address }?.label ?? "" }
    func displayOperands(_ ins: Instruction) -> String {
        guard !ins.target.isEmpty, let f = codeIndex.functionsByAddress[ins.target] else { return ins.operands }
        let operands = ins.operands.replacingOccurrences(of: "\\s*<[^>]*>", with: "", options: .regularExpression)
        return operands + " <" + f.name + ">"
    }
    func setAnnotation(address: String, label: String, comment: String, bookmark: Bool) {
        guard addressValue(address) != nil else { error = "Enter a hexadecimal address"; return }
        let canonical = "0x" + String(addressValue(address)!, radix: 16)
        annotations.removeAll { $0.address == canonical }
        if !label.isEmpty || !comment.isEmpty || bookmark { annotations.append(Annotation(address: canonical, label: label, comment: comment, bookmark: bookmark)) }
        dirty = true
    }
    func saveProject() {
        guard let a = analysis else { return }
        var destination = projectURL
        if destination == nil {
            let panel = NSSavePanel(); panel.nameFieldStringValue = a.name + ".asteria.json"
            if panel.runModal() == .OK { destination = panel.url }
        }
        guard let destination else { return }
        do {
            // keep the path relative when the binary sits beside the project, so the pair can move together
            let folder = destination.deletingLastPathComponent().standardizedFileURL.path
            let binaryPath = URL(fileURLWithPath: a.path).standardizedFileURL.path
            let storedPath = binaryPath.hasPrefix(folder + "/") ? String(binaryPath.dropFirst(folder.count + 1)) : a.path
            let project = ProjectFile(path: storedPath, sha256: a.sha256, slice: a.selectedSlice, annotations: annotations, decompilerNames: decompilerNames, functionNames: functionNames, followCode: followCode)
            let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            try encoder.encode(project).write(to: destination, options: .atomic)
            projectURL = destination; dirty = false; status = "Project saved"
        } catch { self.error = error.localizedDescription }
    }
    func loadProject(_ url: URL) {
        do {
            let p = try JSONDecoder().decode(ProjectFile.self, from: Data(contentsOf: url))
            guard p.version == 1 else { throw EngineError(message: "Unsupported project schema") }
            let folder = url.deletingLastPathComponent()
            var binary = URL(fileURLWithPath: p.path, relativeTo: folder).standardizedFileURL
            // projects saved elsewhere carry an absolute path; fall back to the same name next to the project file
            if !FileManager.default.fileExists(atPath: binary.path) {
                let sibling = folder.appendingPathComponent(URL(fileURLWithPath: p.path).lastPathComponent)
                if FileManager.default.fileExists(atPath: sibling.path) { binary = sibling }
            }
            open(binary, slice: p.slice, restored: p, project: url)
        } catch { self.error = error.localizedDescription }
    }
    func exportReport(json: Bool = false) {
        guard let a = analysis else { return }
        let panel = NSSavePanel(); panel.nameFieldStringValue = a.name + (json ? "-analysis.json" : "-report.md")
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            if json {
                let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]; try encoder.encode(a).write(to: url, options: .atomic)
            } else {
                var text = "# Asteria analysis: \(a.name)\n\nFormat: \(a.format) · \(a.arch) · \(a.bits)-bit\n\nPath: `\(a.path)`\n\nSHA-256: `\(a.sha256)`\n\nSize: \(a.size) bytes · Entropy: \(a.entropy) · Entry: \(a.entry)\n\n## Metadata\n\n"
                text += a.headers.map { "- \($0.name): \($0.value)" }.joined(separator: "\n")
                text += "\n\n## Sections\n\n" + a.sections.map { "- \($0.name): VA \($0.address), file \(hex($0.offset)), \($0.size) bytes, \($0.flags), entropy \($0.entropy)" }.joined(separator: "\n")
                text += "\n\n## Dependencies\n\n" + a.libraries.map { "- \($0)" }.joined(separator: "\n")
                text += "\n\n## Analyst notes\n\n" + annotations.map { "### \($0.address) \($0.label)\n\n\($0.comment)\n" }.joined(separator: "\n")
                text += "\n\n## Analysis limitations\n\n" + a.warnings.map { "- \($0)" }.joined(separator: "\n") + "\n\nGenerated by Asteria 0.3. Static analysis does not establish runtime behavior. Export JSON for full tables.\n"
                try text.write(to: url, atomically: true, encoding: .utf8)
            }
            status = "Report exported"
        } catch { self.error = error.localizedDescription }
    }
    var decompilerFunction: BinaryFunction? {
        guard let a = analysis else { return nil }
        return codeIndex.functionsByAddress[pseudoFunctionAddress] ?? a.functions.first { f in
            guard let address = addressValue(pseudoAddress), let start = addressValue(f.address), let end = addressValue(f.end) else { return false }
            return start <= address && address <= end
        } ?? a.functions.first
    }
    var decompilerNameKey: String { "\(analysis?.selectedSlice ?? 0):\(decompilerFunction?.address ?? "")" }
    var decompilerRequestKey: String { "\(analysis?.sha256 ?? ""):\(decompilerNameKey):\(decompilerABI)" }
    var selectedPseudocode: PseudocodeLine? { selectedPseudoLine.flatMap { pseudoLines[$0] } }
    var linkedAddresses: Set<String> { followCode ? pseudoAddresses : [] }
    var activeFunctionNames: [String: String] { functionNames[String(analysis?.selectedSlice ?? 0)] ?? [:] }
    func function(at address: String) -> BinaryFunction? {
        if let ins = codeIndex.instructionsByAddress[address], let f = codeIndex.functionsByName[ins.function] { return f }
        guard let value = addressValue(address) else { return nil }
        return functions.first { (addressValue($0.address) ?? UInt64.max) <= value && (addressValue($0.end) ?? 0) >= value }
    }
    func setFollowCode(_ enabled: Bool) {
        followCode = enabled; UserDefaults.standard.set(enabled, forKey: "followCode")
        if analysis != nil { dirty = true }
        if enabled {
            if page == "Decompiler", let f = decompilerFunction { selectedFunction = f.name; selectedAddress = pseudoAddress.isEmpty ? f.address : pseudoAddress }
            else { syncPseudocode(to: selectedAddress.isEmpty ? selectedInstructions.first?.address ?? "" : selectedAddress) }
        }
    }
    func selectFunction(_ name: String, pseudocode: Bool = false) {
        let f = codeIndex.functionsByName[name]
        renameTarget = f.map { RenameTarget(functionAddress: $0.address) }
        if pseudocode {
            pseudoFunctionAddress = f?.address ?? ""; pseudoAddress = f?.address ?? ""; selectedPseudoLine = nil
            if followCode { selectedFunction = name; selectedAddress = pseudoAddress }
        } else {
            selectedFunction = name; selectedAddress = f?.address ?? ""
            if followCode { syncPseudocode(to: selectedAddress) }
        }
    }
    func syncPseudocode(to address: String) {
        pseudoAddress = address
        if let f = function(at: address) { pseudoFunctionAddress = f.address }
        mapPseudoAddress(address)
    }
    func showPseudocode(_ address: String? = nil) {
        if let address { syncPseudocode(to: address); if followCode { selectedAddress = address; selectedFunction = decompilerFunction?.name ?? "" } }
        else if pseudoFunctionAddress.isEmpty { syncPseudocode(to: selectedAddress) }
        mode = "Static"; page = "Decompiler"
    }
    func decompileSelected(force: Bool = false) {
        guard let a = analysis, let function = decompilerFunction else { return }
        decompileTask?.cancel(); decompilerToken = UUID()
        pseudoFunctionAddress = function.address
        if followCode { selectedFunction = function.name }
        let key = decompilerRequestKey
        if !force, let cached = decompilerCache[key] {
            touchDecompilerCache(key)
            decompilation = cached; decompiling = false; decompilerError = ""; mapPseudoAddress(pseudoAddress)
            status = "Decompiler · \(cached.coverage.mapped)/\(cached.coverage.total) instructions mapped · \(cached.coverage.unsupported) unsupported"
            return
        }
        let token = UUID(); decompilerToken = token
        decompiling = true; decompilerError = ""; decompilation = nil; selectedPseudoLine = nil
        let names = decompilerNames[decompilerNameKey] ?? [:]
        let functionNames = activeFunctionNames, abi = decompilerABI
        decompileTask = Task {
            do {
                // Let rapid keyboard/list navigation settle before scheduling CPU
                // work. Cancelled selections never wait ahead of the latest one.
                if !force { try await Task.sleep(for: .milliseconds(75)) }
                try Task.checkCancellation()
                let result = try await EngineClient.request(["action": "decompile", "path": a.path, "function": function.address, "slice": a.selectedSlice, "sha256": a.sha256, "abi": abi, "names": names, "functionNames": functionNames], as: Decompilation.self)
                guard decompilerToken == token && decompilerRequestKey == key else { return }
                cacheDecompiler(result, key: key); decompilation = result
                mapPseudoAddress(pseudoAddress)
                status = "Decompiler · \(result.coverage.mapped)/\(result.coverage.total) instructions mapped · \(result.coverage.unsupported) unsupported"
            } catch is CancellationError { }
            catch { if decompilerToken == token { decompilerError = error.localizedDescription } }
            if decompilerToken == token { decompiling = false }
        }
    }
    private func touchDecompilerCache(_ key: String) {
        decompilerOrder.removeAll { $0 == key }; decompilerOrder.append(key)
    }
    private func clearDecompilerCache() {
        decompilerCache.removeAll(); decompilerOrder.removeAll()
    }
    private func cacheDecompiler(_ result: Decompilation, key: String) {
        decompilerCache[key] = result; touchDecompilerCache(key)
        while decompilerOrder.count > 24 {
            decompilerCache.removeValue(forKey: decompilerOrder.removeFirst())
        }
    }
    func cancelDecompilation() {
        decompileTask?.cancel(); decompilerToken = UUID(); decompiling = false
        status = "Decompilation cancelled"
    }
    func selectPseudocode(_ line: PseudocodeLine) {
        selectedPseudoLine = line.id
        renameTarget = decompilerFunction.map { RenameTarget(functionAddress: $0.address) }
        if let first = line.addresses.first { pseudoAddress = first; if followCode { selectedAddress = first; selectedFunction = decompilerFunction?.name ?? "" } }
    }
    func selectDecompilerAddress(_ address: String) {
        selectedAddress = address; renameTarget = nil
        if followCode { syncPseudocode(to: address) }
    }
    func mapPseudoAddress(_ address: String) {
        guard let result = decompilation else { return }
        let matches = (result.reverseMap[address] ?? []).compactMap { pseudoLines[$0] }
        selectedPseudoLine = matches.sorted { l, r in
            let lp = l.kind == "mechanic" ? 1 : 0, rp = r.kind == "mechanic" ? 1 : 0
            return lp == rp ? l.addresses.count < r.addresses.count : lp < rp
        }.first?.id
    }
    func inspectDecompilerBytes(_ ins: Instruction) {
        guard ins.offset >= 0 else { return }
        showBytes(ins.offset, context: "Pseudocode → \(ins.function) → VA \(ins.address) · \(ins.bytes.split(separator: " ").count) instruction bytes", bytes: ins.bytes)
    }
    func renameDecompilerVariable(_ variable: String, to name: String, reset: Bool = false) {
        guard let a = analysis, let function = decompilerFunction else { return }
        let nameKey = decompilerNameKey, key = decompilerRequestKey
        var names = decompilerNames[nameKey] ?? [:]
        if reset { names.removeValue(forKey: variable) } else { names[variable] = name.trimmingCharacters(in: .whitespacesAndNewlines) }
        let token = UUID(); decompilerToken = token; decompiling = true
        Task {
            do {
                let result = try await EngineClient.request(["action": "decompile", "path": a.path, "function": function.address, "slice": a.selectedSlice, "sha256": a.sha256, "abi": decompilerABI, "names": names, "functionNames": activeFunctionNames], as: Decompilation.self)
                guard decompilerToken == token && decompilerRequestKey == key else { return }
                decompilerNames[nameKey] = names; dirty = true; decompilation = result; clearDecompilerCache(); cacheDecompiler(result, key: key)
                status = "Decompiler variable name updated · save the project to retain it"
            } catch { if decompilerToken == token { self.error = error.localizedDescription } }
            if decompilerToken == token { decompiling = false }
        }
    }
    func exportDecompilation(json: Bool = false) {
        guard let result = decompilation, let a = analysis else { return }
        let panel = NSSavePanel(); panel.nameFieldStringValue = result.function.name + (json ? "-decompilation.json" : "-pseudocode.c")
        guard panel.runModal() == .OK, let url = panel.url else { return }
        guard url.standardizedFileURL.path != URL(fileURLWithPath: a.path).standardizedFileURL.path else { error = "Choose a different file from the analyzed binary"; return }
        do {
            if json { let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]; try encoder.encode(result).write(to: url, options: .atomic) }
            else { try result.text.write(to: url, atomically: true, encoding: .utf8) }
            status = "Decompiler export saved"
        } catch { self.error = error.localizedDescription }
    }
    func beginRename(_ explicit: RenameTarget? = nil, instruction: String? = nil) {
        guard let a = analysis, !renameBusy else { return }
        let target = explicit ?? (instruction == nil ? renameTarget : nil)
        let address = instruction ?? (target == nil ? selectedAddress : "")
        guard let f = target.flatMap({ codeIndex.functionsByAddress[$0.functionAddress] }) ?? function(at: address) ?? (page == "Decompiler" ? decompilerFunction : codeIndex.functionsByName[selectedFunction]) else { return }
        renameBusy = true; renameError = ""
        let key = "\(a.selectedSlice):\(f.address)", token = generation
        Task {
            var variables: [RecoveredVariable] = []
            do {
                let cacheKey = "\(a.sha256):\(key):\(decompilerABI)"
                if let cached = decompilerCache[cacheKey] {
                    touchDecompilerCache(cacheKey); variables = cached.variables
                } else {
                    let result = try await EngineClient.request(["action": "decompile", "path": a.path, "function": f.address, "slice": a.selectedSlice, "sha256": a.sha256, "abi": decompilerABI, "names": decompilerNames[key] ?? [:], "functionNames": activeFunctionNames], as: Decompilation.self)
                    guard generation == token else { renameBusy = false; return }
                    cacheDecompiler(result, key: cacheKey); variables = result.variables
                }
            } catch { renameError = "Function renaming is available. Recovered variables could not be loaded: \(error.localizedDescription)" }
            guard generation == token else { renameBusy = false; return }
            // Instruction selection can denote several values. Offer those first,
            // without guessing that a machine register always holds one variable.
            variables.sort { l, r in
                let lp = l.addresses.contains(address), rp = r.addresses.contains(address)
                return lp == rp ? l.displayName < r.displayName : lp
            }
            renameContext = RenameContext(function: f, variables: variables, selected: target?.variable ?? "", instruction: address)
            renameBusy = false
        }
    }
    func commitRename(_ context: RenameContext, variable: String, name: String, reset: Bool = false) {
        guard let a = analysis, !renameBusy else { return }
        let token = generation, value = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let key = "\(a.selectedSlice):\(context.function.address)"
        var candidateFunctions = activeFunctionNames, candidateVariables = decompilerNames[key] ?? [:]
        if variable.isEmpty {
            if reset { candidateFunctions.removeValue(forKey: context.function.address) } else { candidateFunctions[context.function.address] = value }
        } else {
            if reset { candidateVariables.removeValue(forKey: variable) } else { candidateVariables[variable] = value }
        }
        renameBusy = true; renameError = ""
        Task {
            do {
                if variable.isEmpty {
                    let next = try await EngineClient.request(["action": "analyze", "path": a.path, "slice": a.selectedSlice, "functionNames": candidateFunctions], as: Analysis.self)
                    guard next.sha256 == a.sha256 else { throw EngineError(message: "Binary changed; reopen it before renaming") }
                    guard generation == token else { renameBusy = false; return }
                    let disAddress = functions.first { $0.name == selectedFunction }?.address
                    functionNames[String(a.selectedSlice)] = candidateFunctions; analysis = next
                    if let disAddress { selectedFunction = next.functions.first { $0.address == disAddress }?.name ?? "" }
                    clearDecompilerCache(); decompileSelected(force: true)
                } else {
                    let result = try await EngineClient.request(["action": "decompile", "path": a.path, "function": context.function.address, "slice": a.selectedSlice, "sha256": a.sha256, "abi": decompilerABI, "names": candidateVariables, "functionNames": candidateFunctions], as: Decompilation.self)
                    guard generation == token else { renameBusy = false; return }
                    decompilerNames[key] = candidateVariables; clearDecompilerCache()
                    if decompilerFunction?.address == context.function.address { decompilerToken = UUID(); decompiling = false; decompilation = result; cacheDecompiler(result, key: decompilerRequestKey) }
                }
                dirty = true; renameContext = nil; status = reset ? "Original name restored · save the project to retain it" : "Name updated in code views · save the project to retain it"
            } catch { renameError = error.localizedDescription }
            renameBusy = false
        }
    }
    func importSignatures() {
        let panel = NSOpenPanel(); panel.message = "Import an Asteria Atlas signature pack (.atlas.json)"; panel.allowsMultipleSelection = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        Task {
            do {
                let result = try await EngineClient.request(["action": "signatureInstall", "path": url.path], as: SignatureInstallation.self)
                status = "Installed \(result.count) signatures from \(result.library)"
                refreshRecognition()
            } catch { self.error = error.localizedDescription }
        }
    }
    func exportSignatures() {
        guard let a = analysis else { return }
        status = "Learning named functions…"
        Task {
            do {
                let learned = try await EngineClient.request(["action": "signatureLearn", "path": a.path, "slice": a.selectedSlice, "sha256": a.sha256, "library": a.name, "functionNames": activeFunctionNames], as: SignatureLearning.self)
                guard learned.count > 0 else { throw EngineError(message: "No eligible named functions. Signatures require at least 4 instructions and 16 bytes, unique addresses, and resolved code references. Rename a function first, or open a binary with symbols.") }
                let panel = NSSavePanel(); panel.nameFieldStringValue = a.name + ".atlas.json"
                guard panel.runModal() == .OK, let url = panel.url else { return }
                guard url.standardizedFileURL.path != URL(fileURLWithPath: a.path).standardizedFileURL.path else { throw EngineError(message: "Choose a different file from the analyzed binary") }
                let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
                try encoder.encode(learned.pack).write(to: url, options: .atomic)
                status = "Exported \(learned.count) signatures · \(learned.skipped.count) ineligible functions skipped"
            } catch { self.error = error.localizedDescription }
        }
    }
    func refreshRecognition() {
        guard let a = analysis else { return }
        let token = generation
        Task {
            do {
                let next = try await EngineClient.request(["action": "analyze", "path": a.path, "slice": a.selectedSlice, "functionNames": activeFunctionNames, "refresh": true], as: Analysis.self)
                guard generation == token else { return }
                guard next.sha256 == a.sha256 else { throw EngineError(message: "Binary changed; reopen it before applying signatures") }
                let address = functions.first { $0.name == selectedFunction }?.address
                analysis = next
                if let address { selectedFunction = next.functions.first { $0.address == address }?.name ?? "" }
                clearDecompilerCache(); if page == "Decompiler" { decompileSelected(force: true) }
                status = "Atlas · \(next.recognition?.matches.filter { $0.applied }.count ?? 0) functions identified · \(next.recognition?.ambiguities.count ?? 0) ambiguous matches"
            } catch { self.error = error.localizedDescription }
        }
    }
    func debugAction(_ action: String, _ arguments: [String: Any] = [:], quiet: Bool = false) {
        if quiet {
            if debugBusy || pollingBusy { return }
            pollingBusy = true
        } else {
            if debugBusy { return }
            debugBusy = true
        }
        Task {
            do {
                var query = arguments; query["action"] = action
                let next = try await debugger.request(query)
                if next.state != debug.state { status = next.description }
                debug = next; debugStarted = true
                debugTargetPath = next.targetPath; debugTargetPlatform = next.platform
                if !next.output.isEmpty { console += next.output }
                if !next.result.isEmpty { console += next.result + "\n" }
                if console.count > 300000 { console = String(console.suffix(250000)) }
                if !quiet { status = next.description }
                startPolling()
            } catch {
                if !quiet { self.error = error.localizedDescription }
                else { status = error.localizedDescription; debugStarted = false; pollTask?.cancel(); pollTask = nil }
            }
            if quiet { pollingBusy = false } else { debugBusy = false }
        }
    }
    func startPolling() {
        guard pollTask == nil else { return }
        pollTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 700_000_000)
                guard !Task.isCancelled, let self else { break }
                if self.debugStarted && !self.debugBusy { self.debugAction("snapshot", quiet: true) }
            }
        }
    }
    func copy(_ value: String) { NSPasteboard.general.clearContents(); NSPasteboard.general.setString(value, forType: .string) }
}
