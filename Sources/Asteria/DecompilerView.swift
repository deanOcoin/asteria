import AppKit
import SwiftUI

struct DecompilerView: View {
    @EnvironmentObject var w: Workspace
    let a: Analysis
    @State private var showFunctions = true
    @State private var showMechanics = false
    @State private var wrapCode = true
    @State private var query = ""
    @State private var detail = "Provenance"
    @State private var patchInstruction: Instruction?
    @State private var variablesOpen = false
    var selectedInstruction: Instruction? { w.codeIndex.instructionsByAddress[w.selectedAddress] }
    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider().opacity(0.35)
            HSplitView {
                if showFunctions { FunctionList(a: a, pseudocode: true).frame(minWidth: 200, idealWidth: 205, maxWidth: 230) }
                if let result = w.decompilation {
                    VStack(spacing: 0) {
                        HSplitView {
                            pseudocode(result).frame(minWidth: 340)
                            instructions(result).frame(minWidth: 320)
                        }
                        Divider().opacity(0.35)
                        inspector(result).frame(height: 184)
                    }
                } else if w.decompiling {
                    VStack(spacing: 16) { ProgressView(); Text("Lifting instructions and recovering code…"); Text("Preserving the path back to every byte").foregroundStyle(.secondary).font(.caption) }.frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    EmptyPanel(icon: "curlybraces", title: "Select a function to decompile", detail: w.decompilerError.isEmpty ? "ARM64 and x86/x64 scalar integer code. Each pseudocode statement links to its contributing instructions and file offsets." : w.decompilerError)
                }
            }
        }
        .task(id: w.decompilerRequestKey) { w.decompileSelected() }
        .onDisappear { if w.decompiling { w.cancelDecompilation() } }
        .sheet(item: $patchInstruction) { ins in InstructionPatchSheet(a: a, ins: ins).environmentObject(w) }
        .sheet(isPresented: $variablesOpen) { DecompilerVariablesSheet().environmentObject(w) }
    }
    var toolbar: some View {
        HStack(spacing: 12) {
            Button { showFunctions.toggle() } label: { Image(systemName: "sidebar.left") }.help("Toggle function list")
            VStack(alignment: .leading, spacing: 3) {
                Text(w.decompilerFunction?.name ?? "Original decompiler").font(.system(size: 12, weight: .semibold, design: .monospaced)).lineLimit(1)
                if let c = w.decompilation?.coverage { Text("\(c.mapped)/\(c.total) mapped · \(c.loops) loops · \(c.unsupported) unsupported").help("Mapped counts instructions with provenance links. Unsupported counts effects that the lifter could not model; inspect Diagnostics and asm_effect lines.").font(.system(size: 9, design: .monospaced)).foregroundStyle(c.unsupported > 0 ? Color.atlasGold : Color.atlasMuted) }
            }
            Spacer(minLength: 6)
            FollowCodeToggle()
            Button { w.beginRename() } label: { Image(systemName: "pencil") }.help("Rename the highlighted function or variable (F2). Click a name in pseudocode first, or select an instruction to choose a linked value.")
            Picker("ABI", selection: $w.decompilerABI) {
                Text("Auto ABI").tag("auto")
                if a.arch.hasPrefix("arm64") { Text("AAPCS64").tag("aapcs64") }
                else if a.bits == 64 { Text("System V x64").tag("sysv64"); Text("Windows x64").tag("win64") }
                else { Text("cdecl x86").tag("cdecl32") }
            }.help(Help.text("ABI")).labelsHidden().frame(width: 125)
            Button("Variables") { variablesOpen = true }.help("Browse all recovered values, machine-width types and storage locations. Rename a selected value here or click its name in code and press F2.").disabled(w.decompilation == nil || w.decompiling)
            Menu("Export") { Button("Pseudocode (.c)…") { w.exportDecompilation() }; Button("Code + provenance + IR (.json)…") { w.exportDecompilation(json: true) } }.help("Export pseudocode as C text, or JSON containing code, instruction spans, variables, diagnostics and IR.").disabled(w.decompilation == nil).frame(width: 85)
            Button { w.decompileSelected(force: true) } label: { Image(systemName: "arrow.clockwise") }.help("Discard the cached result and decompile this function again using the current ABI and saved names.").disabled(w.decompiling)
            if w.decompiling {
                ProgressView().controlSize(.small)
                Button { w.cancelDecompilation() } label: { Image(systemName: "xmark.circle") }
                    .help("Cancel this decompilation immediately. You can select another function or use Refresh to retry.")
            }
        }.padding(.horizontal, 14).frame(height: 53).background(Color.atlasPanel.opacity(0.6))
    }
    func pseudocode(_ result: Decompilation) -> some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Text("PSEUDOCODE").font(.system(size: 9, weight: .bold)).tracking(1.4).foregroundStyle(Color.atlasAccent)
                Spacer()
                Toggle("Wrap", isOn: $wrapCode).help(Help.text("Wrap")).toggleStyle(.checkbox).font(.system(size: 10))
                Toggle("Mechanics", isOn: $showMechanics).toggleStyle(.checkbox).font(.system(size: 10)).help("Show frame operations and unused pure definitions")
            }.padding(12)
            HStack { Image(systemName: "magnifyingglass").foregroundStyle(Color.atlasMuted); TextField("Find in pseudocode", text: $query).help(Help.text("Find in pseudocode")).textFieldStyle(.plain).font(.system(size: 11)) }.padding(.horizontal, 12).padding(.bottom, 10)
            Divider().opacity(0.3)
            ScrollViewReader { proxy in
                GeometryReader { geometry in
                ScrollView(wrapCode ? [.vertical] : [.horizontal, .vertical]) {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(result.lines.filter { line in
                            (showMechanics || line.kind != "mechanic" || line.id == w.selectedPseudoLine) && (query.isEmpty || line.text.localizedCaseInsensitiveContains(query))
                        }) { line in
                            Group {
                                HStack(alignment: .top, spacing: 12) {
                                    Button { w.selectPseudocode(line) } label: { Text(String(format: "%3d", line.id + 1)).foregroundStyle(Color.atlasMuted).frame(width: 30, alignment: .trailing) }.buttonStyle(.plain).help("Select line \(line.id + 1) and its contributing instruction spans. Follow controls whether disassembly moves.")
                                    SelectableCodeLine(line: line, result: result, wrap: wrapCode)
                                    Spacer(minLength: 20)
                                }.font(.system(size: 11, design: .monospaced)).padding(.horizontal, 10).padding(.vertical, 4)
                                    .background(line.id == w.selectedPseudoLine ? Color.atlasAccent.opacity(0.13) : .clear).contentShape(Rectangle())
                            }.id(line.id)
                                .accessibilityLabel("Pseudocode line \(line.id + 1): \(line.text)")
                                .contextMenu {
                                    Button("Rename selected name…  F2") { w.beginRename() }
                                    Button("Copy line") { w.copy(line.text) }.help(Help.text("Copy line"))
                                    Button("Copy contributing addresses") { w.copy(line.addresses.joined(separator: "\n")) }.help(Help.text("Copy contributing addresses")).disabled(line.addresses.isEmpty)
                                    Button("Select linked instructions") { w.selectPseudocode(line); if let address = line.addresses.first { w.navigate(address) } }.help(Help.text("Select linked instructions")).disabled(line.addresses.isEmpty)
                                }
                        }
                    }.padding(.vertical, 8).frame(width: wrapCode ? geometry.size.width : nil, alignment: .leading)
                }.onAppear { if let value = w.selectedPseudoLine { proxy.scrollTo(value, anchor: .center) } }.onChange(of: w.selectedPseudoLine) { _, value in if let value { proxy.scrollTo(value, anchor: .center) } }
                }
            }
            HStack { Image(systemName: "link"); Text(w.followCode ? "Click a name · F2 to rename · select a line number to trace bytes" : "Views independent · click a name, then F2 to rename"); Spacer() }.font(.system(size: 9)).foregroundStyle(Color.atlasMuted).padding(10).background(Color.atlasPanel)
        }.background(Color.black.opacity(0.08))
    }
    func instructions(_ result: Decompilation) -> some View {
        VStack(spacing: 0) {
            HStack { Text(w.followCode ? "LINKED DISASSEMBLY" : "INDEPENDENT DISASSEMBLY").font(.system(size: 9, weight: .bold)).tracking(1.3); Spacer(); Text("VA  /  FILE OFFSET").font(.system(size: 8, design: .monospaced)).foregroundStyle(Color.atlasMuted) }.padding(12)
            if !w.followCode {
                Picker("Disassembly function", selection: Binding(get: { w.selectedFunction }, set: { w.selectFunction($0) })) {
                    Text("All instructions").tag("")
                    ForEach(w.functions) { Text($0.name).tag($0.name) }
                }.font(.system(size: 10)).padding(.horizontal, 12).padding(.bottom, 8).help("Browse another function in disassembly while pseudocode stays on its current function.")
            }
            Divider().opacity(0.3)
            ScrollViewReader { proxy in
                ScrollView([.horizontal, .vertical]) {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(w.selectedInstructions) { ins in
                            Button { w.selectDecompilerAddress(ins.address) } label: {
                                HStack(spacing: 12) {
                                    Rectangle().fill(w.selectedAddress == ins.address ? Color.atlasAccent : .clear).frame(width: 2)
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text(ins.address).help("Static virtual address: " + ins.address).foregroundStyle(w.linkedAddresses.contains(ins.address) ? Color.atlasAccent : Color.atlasMuted)
                                        Text(ins.offset >= 0 ? "FILE \(hex(ins.offset))" : "UNMAPPED").help("Exact file offset in the complete binary. UNMAPPED means patch navigation is unavailable for this instruction.").font(.system(size: 8, design: .monospaced)).foregroundStyle(Color.atlasGold.opacity(0.85))
                                    }.frame(width: 106, alignment: .leading)
                                    VStack(alignment: .leading, spacing: 3) {
                                        HStack(spacing: 8) { Text(ins.mnemonic).foregroundStyle(ins.kind == "call" ? Color.atlasAccent : Color.white.opacity(0.85)); Text(w.displayOperands(ins)).help("\(w.displayOperands(ins))\nSelect this instruction and press F2 to rename its function or a recovered value linked to it.").foregroundStyle(Color.white.opacity(0.75)) }
                                        Text(ins.bytes).help("Original machine-code bytes at the displayed file offset.").font(.system(size: 8, design: .monospaced)).foregroundStyle(Color.atlasMuted)
                                    }.fixedSize(horizontal: true, vertical: false)
                                    Spacer(minLength: 12)
                                }.font(.system(size: 10, design: .monospaced)).padding(.horizontal, 7).frame(height: 41)
                                    .background(w.linkedAddresses.contains(ins.address) ? Color.atlasAccent.opacity(0.09) : .clear).contentShape(Rectangle())
                            }.buttonStyle(.plain).id(ins.address)
                                .accessibilityLabel("Instruction \(ins.address), file offset \(hex(ins.offset)), \(ins.mnemonic) \(ins.operands)")
                                .contextMenu {
                                    Button("Rename function / linked variable…  F2") { w.beginRename(instruction: ins.address) }
                                    Button("Hex / patch at \(hex(ins.offset))") { w.inspectDecompilerBytes(ins) }.disabled(ins.offset < 0)
                                    Button("Preview instruction rewrite…") { patchInstruction = ins }.help(Help.text("Preview instruction rewrite…")).disabled(ins.offset < 0 || ins.bytes.isEmpty)
                                    Button("Open in Disassembly") { w.navigate(ins.address) }.help(Help.text("Open in Disassembly"))
                                    Button("Follow target in pseudocode") { w.showPseudocode(ins.target) }.help(Help.text("Follow target in pseudocode")).disabled(ins.target.isEmpty)
                                    Button("Copy file offset") { w.copy(hex(ins.offset)) }.help(Help.text("Copy file offset")).disabled(ins.offset < 0)
                                }
                        }
                    }.padding(.vertical, 6)
                }.onChange(of: w.selectedAddress) { _, value in proxy.scrollTo(value, anchor: .center) }
                .onAppear { proxy.scrollTo(w.selectedAddress, anchor: .center) }
            }
            HStack { Text(w.followCode ? "Mint = contributes to selected pseudocode line" : "Follow off · disassembly selection stays independent"); Spacer() }.font(.system(size: 9)).foregroundStyle(Color.atlasMuted).padding(10).background(Color.atlasPanel)
        }
    }
    func inspector(_ result: Decompilation) -> some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack {
                Picker("Details", selection: $detail) { Text("Provenance").tag("Provenance"); Text("Diagnostics").tag("Diagnostics"); Text("Lifted IR").tag("Lifted IR") }.help(Help.text("Details")).pickerStyle(.segmented).labelsHidden().frame(width: 285)
                Spacer()
                if let ins = selectedInstruction {
                    Button("Copy offset") { w.copy(hex(ins.offset)) }.help(Help.text("Copy offset")).disabled(ins.offset < 0)
                    Button("Hex / Patch") { w.inspectDecompilerBytes(ins) }.help(Help.text("Hex / Patch")).disabled(ins.offset < 0)
                    Button("Instruction rewrite…") { patchInstruction = ins }.help(Help.text("Instruction rewrite…")).disabled(ins.offset < 0 || ins.bytes.isEmpty)
                }
            }
            if detail == "Diagnostics" {
                ScrollView { VStack(alignment: .leading, spacing: 7) { ForEach(result.diagnostics, id: \.self) { text in Label(text, systemImage: "info.circle").font(.system(size: 11)).foregroundStyle(Color.atlasGold.opacity(0.9)).fixedSize(horizontal: false, vertical: true) } }.frame(maxWidth: .infinity, alignment: .leading) }
            } else if detail == "Lifted IR" {
                let rows = result.ir.filter { op in !Set(op.addresses).isDisjoint(with: w.linkedAddresses) }
                MonoText(text: rows.map { "\($0.addresses.joined(separator: ", "))  \($0.kind)  \($0.destination)  \($0.expression) \($0.arguments.joined(separator: ", "))" }.joined(separator: "\n"))
            } else {
                if let line = w.selectedPseudocode {
                    Text("LINE \(line.id + 1) · \(line.addresses.count) contributing instructions · \(line.spans.count) exact instruction spans").font(.system(size: 10, weight: .semibold, design: .monospaced)).foregroundStyle(Color.atlasAccent)
                    Text(line.explanation).font(.system(size: 11)).foregroundStyle(.secondary)
                    if let ins = selectedInstruction {
                        HStack(spacing: 22) {
                            VStack(alignment: .leading, spacing: 5) { Text("VIRTUAL ADDRESS").font(.system(size: 8)).foregroundStyle(Color.atlasMuted); Text(ins.address).font(.system(size: 12, design: .monospaced)) }
                            VStack(alignment: .leading, spacing: 5) { Text("FILE OFFSET").font(.system(size: 8)).foregroundStyle(Color.atlasMuted); Text(ins.offset >= 0 ? hex(ins.offset) : "Unmapped").font(.system(size: 12, design: .monospaced)).foregroundStyle(Color.atlasGold) }
                            VStack(alignment: .leading, spacing: 5) { Text("SELECTED INSTRUCTION BYTES").font(.system(size: 8)).foregroundStyle(Color.atlasMuted); Text(ins.bytes).help("Original machine-code bytes at the displayed file offset.").font(.system(size: 11, design: .monospaced)).textSelection(.enabled) }
                        }.padding(.top, 2)
                    }
                    Text("A line can span separate byte ranges. Select the exact instruction before patching.").font(.system(size: 10)).foregroundStyle(Color.atlasMuted)
                } else { Text("Select either a pseudocode line or an instruction. Structural braces and declarations may have no direct bytes.").font(.callout).foregroundStyle(.secondary) }
            }
            Spacer(minLength: 0)
        }.padding(14).background(Color.atlasPanel.opacity(0.7))
    }
}

private enum PseudocodeHighlight {
    static let rules: [(NSRegularExpression, Color)] = [("\\b(if|else|return|while|break|continue|goto|true|false)\\b", Color.atlasAccent), ("\\b(uint[0-9]+_t|int[0-9]+_t|bool|void)\\b", Color(red: 0.55, green: 0.68, blue: 0.94)), ("\\b(0x[0-9a-fA-F]+|[0-9]+)\\b", Color.atlasGold)] .map { (try! NSRegularExpression(pattern: $0.0), $0.1) }
}

func coloredCode(_ line: PseudocodeLine) -> AttributedString {
    var string = AttributedString(line.text)
    string.foregroundColor = ["unsupported", "uncertain"].contains(line.kind) ? Color.atlasGold : (line.kind == "mechanic" || line.kind == "comment" ? Color.atlasMuted : Color.white.opacity(0.85))
    guard !["mechanic", "comment"].contains(line.kind) else { return string }
    for (regex, color) in PseudocodeHighlight.rules {
        for match in regex.matches(in: line.text, range: NSRange(line.text.startIndex..., in: line.text)) {
            if let range = Range(match.range, in: line.text), let lower = AttributedString.Index(range.lowerBound, within: string), let upper = AttributedString.Index(range.upperBound, within: string) { string[lower..<upper].foregroundColor = color }
        }
    }
    return string
}

struct DecompilerVariablesSheet: View {
    @EnvironmentObject var w: Workspace
    @Environment(\.dismiss) var dismiss
    @State private var selected = ""
    @State private var name = ""
    var variable: RecoveredVariable? { w.decompilation?.variables.first { $0.name == selected } }
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack { Text("Recovered variables").font(.title2); Spacer(); Button("Done") { dismiss() }.help(Help.text("Done")).keyboardShortcut(.cancelAction) }
            Text("Names are analyst display overrides, saved with the project. Storage and machine-width types remain visible.").font(.callout).foregroundStyle(.secondary)
            List(selection: $selected) {
                ForEach(w.decompilation?.variables ?? []) { v in
                    HStack { Text(v.displayName).frame(width: 140, alignment: .leading); Text(v.type).foregroundStyle(Color.atlasAccent).frame(width: 85, alignment: .leading); Text(v.storage).foregroundStyle(.secondary); Spacer(); Text(v.kind).foregroundStyle(Color.atlasMuted) }.font(.system(size: 11, design: .monospaced)).tag(v.name).help("\(v.displayName): \(v.type), \(v.storage), \(v.kind). Select to edit the display name; storage identity stays fixed.")
                }
            }.frame(height: 280)
            HStack { TextField("C identifier", text: $name).help(Help.text("C identifier")); Button("Rename") { w.renameDecompilerVariable(selected, to: name) }.help(Help.text("Rename")).disabled(variable == nil || name.isEmpty || w.decompiling); Button("Reset") { w.renameDecompilerVariable(selected, to: "", reset: true) }.help(Help.text("Reset")).disabled(variable == nil || w.decompiling) }
            if let variable { Text("Storage identity: \(variable.name) · \(variable.storage)").font(.caption).foregroundStyle(.secondary) }
        }.padding(24).frame(width: 680).onChange(of: selected) { _, _ in name = variable?.displayName ?? "" }
    }
}

struct InstructionPatchSheet: View {
    @EnvironmentObject var w: Workspace
    @Environment(\.dismiss) var dismiss
    let a: Analysis
    let ins: Instruction
    @State private var kind = "nop"
    @State private var value = ""
    @State private var preview: InstructionPatchPreview?
    @State private var busy = false
    @State private var issue = ""
    @State private var savedPath = ""
    var body: some View {
        VStack(alignment: .leading, spacing: 15) {
            HStack { Text("Instruction rewrite").font(.title2); Spacer(); Button("Done") { dismiss() }.help(Help.text("Done")).keyboardShortcut(.cancelAction) }
            Text("\(ins.address) · file \(hex(ins.offset)) · \(ins.function)").font(.system(size: 11, design: .monospaced)).foregroundStyle(Color.atlasAccent)
            Text(ins.mnemonic + " " + ins.operands).font(.system(size: 13, design: .monospaced)).textSelection(.enabled)
            Text("Original bytes: \(ins.bytes)").font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary)
            Picker("Rewrite", selection: $kind) { Text("Replace with NOPs").tag("nop"); Text("Invert conditional branch").tag("invert"); Text("Always take conditional branch").tag("always"); Text("Change encoded immediate").tag("immediate") }.help(Help.text("Rewrite")).onChange(of: kind) { _, _ in preview = nil; issue = "" }
            if kind == "immediate" {
                TextField("Integer field value (decimal or 0x hex)", text: $value).help(Help.text("Integer field value (decimal or 0x hex)")).onChange(of: value) { _, _ in preview = nil }
                Text("Preserves field width and existing shift. Supported: ARM64 MOV-wide / ADD / SUB; selected x86 integer immediates.").font(.caption).foregroundStyle(.secondary)
            }
            Button("Preview and verify decoding") { prepare() }.help(Help.text("Preview and verify decoding")).buttonStyle(.borderedProminent).disabled(busy)
            if busy { ProgressView().controlSize(.small) }
            if !issue.isEmpty { Text(issue).font(.callout).foregroundStyle(Color.atlasGold).fixedSize(horizontal: false, vertical: true) }
            if let preview {
                Divider()
                Text("REPLACEMENT · \(preview.size) BYTES").font(.system(size: 9, weight: .bold)).tracking(1)
                Text(preview.after).font(.system(size: 14, design: .monospaced)).foregroundStyle(Color.atlasAccent).textSelection(.enabled)
                Text(preview.replacement).font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                Text(preview.warning).font(.caption).foregroundStyle(.secondary)
                HStack { Button("Copy replacement bytes") { w.copy(preview.after) }; Spacer(); Button("Export patched copy…") { save(preview) }.buttonStyle(.borderedProminent).disabled(busy) }
            }
            if !savedPath.isEmpty { HStack { Text("Patched copy saved").foregroundStyle(Color.atlasAccent); Spacer(); Button("Analyze patched copy") { dismiss(); w.open(URL(fileURLWithPath: savedPath)) } } }
            Text("Each preview rewrites one selected instruction span. It does not compile edited pseudocode or relocate code.").font(.system(size: 10)).foregroundStyle(Color.atlasMuted)
        }.padding(26).frame(width: 630)
    }
    func prepare() {
        busy = true; issue = ""; preview = nil
        let requestKind = kind, requestValue = value
        Task {
            do { let result = try await EngineClient.request(["action": "patchPreview", "path": a.path, "address": ins.address, "section": ins.section, "slice": a.selectedSlice, "sha256": a.sha256, "kind": requestKind, "value": requestValue], as: InstructionPatchPreview.self); if kind == requestKind && value == requestValue { preview = result } }
            catch { issue = error.localizedDescription }
            busy = false
        }
    }
    func save(_ preview: InstructionPatchPreview) {
        let panel = NSSavePanel(); panel.nameFieldStringValue = a.name + ".patched"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        busy = true
        Task { do { let result = try await EngineClient.request(["action": "patch", "path": a.path, "output": url.path, "offset": preview.offset, "bytes": preview.after, "sha256": preview.sha256], as: PatchResult.self); savedPath = result.path; w.status = "Patched copy saved · \(result.count) bytes" } catch { issue = error.localizedDescription }; busy = false }
    }
}
