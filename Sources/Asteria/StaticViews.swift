import AppKit
import SwiftUI
import Charts

struct StaticWorkspace: View {
    @EnvironmentObject var w: Workspace
    var body: some View {
        if let a = w.analysis {
            switch w.page {
            case "Overview": OverviewView(a: a)
            case "Disassembly": DisassemblyView(a: a)
            case "Decompiler": DecompilerView(a: a)
            case "Library Recognition": RecognitionView(a: a)
            case "Control Flow": GraphView(a: a)
            case "Sections": SectionsView(a: a)
            case "Symbols": SymbolsView(symbols: a.symbols)
            case "Imports & Exports": ImportsView(a: a)
            case "Strings": StringsView(a: a)
            case "Hex & Patch": HexView(a: a)
            case "Search": SearchView(a: a)
            case "Compare": CompareView(a: a)
            case "Notes": NotesView()
            default: OverviewView(a: a)
            }
        }
    }
}
struct FilterBar: View {
    @Binding var text: String
    var placeholder = "Filter…"
    var count: Int
    var body: some View {
        HStack { Image(systemName: "magnifyingglass").foregroundStyle(Color.atlasMuted); TextField(placeholder, text: $text).textFieldStyle(.plain).help(placeholder + ". Matching is case-insensitive and only filters this table; it does not search the raw file."); Spacer(); Text("\(count.formatted()) items").help("Number of rows that match the current table filters.").font(.system(size: 10, design: .monospaced)).foregroundStyle(Color.atlasMuted) }.padding(.horizontal, 18).frame(height: 41).background(Color.white.opacity(0.018))
    }
}
struct OverviewView: View {
    @EnvironmentObject var w: Workspace
    let a: Analysis
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                HStack(spacing: 14) {
                    MetricCard(title: "FORMAT", value: a.format, detail: "\(a.arch) · \(a.bits)-bit", icon: "doc.viewfinder", color: .atlasAccent)
                    MetricCard(title: "CODE DISCOVERED", value: a.functions.count.formatted(), detail: "\(a.instructions.count.formatted()) instructions", icon: "function", color: .atlasGold)
                    MetricCard(title: "STRINGS", value: a.strings.count.formatted(), detail: "ASCII + UTF-16", icon: "text.quote", color: .blue)
                    MetricCard(title: "FILE ENTROPY", value: String(format: "%.2f", a.entropy), detail: "bits / byte · maximum 8", icon: "waveform.path", color: .purple)
                }
                VStack(alignment: .leading, spacing: 16) {
                    smallHeading("FILE PROFILE", detail: "\(humanSize(a.size))  ·  \(a.sections.count) sections  ·  \(a.imports.count) imports")
                    HStack(alignment: .top, spacing: 32) {
                        VStack(alignment: .leading, spacing: 12) { profile("Entry point", a.entry); profile("Image base", a.imageBase); profile("Byte order", a.endian + " endian"); profile("Path", a.path) }.frame(maxWidth: .infinity, alignment: .leading)
                        VStack(alignment: .leading, spacing: 10) {
                            Text("ENTROPY ACROSS FILE").font(.system(size: 9, weight: .medium)).tracking(1).foregroundStyle(Color.atlasMuted)
                            Chart(Array(a.entropyBins.enumerated()), id: \.offset) { item in
                                AreaMark(x: .value("Offset", item.element.offset), y: .value("Entropy", item.element.value)).foregroundStyle(LinearGradient(colors: [.atlasAccent.opacity(0.25), .atlasAccent.opacity(0.01)], startPoint: .top, endPoint: .bottom))
                                LineMark(x: .value("Offset", item.element.offset), y: .value("Entropy", item.element.value)).foregroundStyle(Color.atlasAccent).lineStyle(StrokeStyle(lineWidth: 1.3))
                            }.help("Each point measures byte entropy in a file range. The horizontal axis follows file offsets; the vertical scale is 0–8 bits per byte.").chartYScale(domain: 0...8).chartXAxis(.hidden).chartYAxis { AxisMarks(values: [0,4,8]) }.frame(height: 105)
                            Text("High entropy can indicate compression or encryption; it is not a verdict.").font(.system(size: 10)).foregroundStyle(.secondary)
                        }.frame(maxWidth: .infinity)
                    }
                    Divider().opacity(0.4)
                    profile("SHA-256", a.sha256); profile("MD5", a.md5)
                }.padding(20).background(Color.atlasPanel, in: RoundedRectangle(cornerRadius: 9))
                HStack(alignment: .top, spacing: 16) {
                    VStack(alignment: .leading, spacing: 14) {
                        smallHeading("FORMAT METADATA")
                        ForEach(a.headers) { row in HStack(alignment: .top) { Text(row.name).help("Binary header field: " + row.name + ". Value: " + row.value).foregroundStyle(.secondary).frame(width: 140, alignment: .leading); Text(row.value).textSelection(.enabled); Spacer() }.font(.system(size: 11)) }
                    }.padding(20).frame(maxWidth: .infinity, alignment: .topLeading).background(Color.atlasPanel, in: RoundedRectangle(cornerRadius: 9))
                    VStack(alignment: .leading, spacing: 14) {
                        smallHeading("LINKED LIBRARIES", detail: "\(a.libraries.count)")
                        if a.libraries.isEmpty { Text("No library dependencies found").font(.callout).foregroundStyle(.secondary) }
                        ForEach(Array(a.libraries.enumerated()), id: \.offset) { _, library in Label(library, systemImage: "shippingbox").help("Dependency recorded in binary metadata: " + library).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary).textSelection(.enabled) }
                    }.padding(20).frame(maxWidth: .infinity, alignment: .topLeading).background(Color.atlasPanel, in: RoundedRectangle(cornerRadius: 9))
                }
                if !a.members.isEmpty {
                    VStack(alignment: .leading, spacing: 10) { smallHeading("ARCHIVE MEMBERS"); ForEach(a.members.prefix(2000)) { m in HStack { Text(m.name); Spacer(); Text(hex(m.offset)); Text(humanSize(m.size)).frame(width: 100, alignment: .trailing) }.font(.system(size: 11, design: .monospaced)) } }.padding(20).background(Color.atlasPanel, in: RoundedRectangle(cornerRadius: 9))
                }
                if !a.warnings.isEmpty {
                    VStack(alignment: .leading, spacing: 10) { smallHeading("ANALYSIS NOTES"); ForEach(Array(a.warnings.enumerated()), id: \.offset) { _, text in Label(text, systemImage: "info.circle").font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true) } }.padding(20).frame(maxWidth: .infinity, alignment: .leading).background(Color.atlasGold.opacity(0.045), in: RoundedRectangle(cornerRadius: 9))
                }
            }.padding(22)
        }
    }
    func profile(_ label: String, _ value: String) -> some View { HStack(alignment: .top) { Text(label).font(.system(size: 11)).foregroundStyle(Color.atlasMuted).frame(width: 85, alignment: .leading); Text(value).font(.system(size: 10, design: .monospaced)).textSelection(.enabled).lineLimit(3) }.help(Help.text(label)) }
    func smallHeading(_ title: String, detail: String = "") -> some View { HStack { Text(title).tracking(1.4); Spacer(); Text(detail).foregroundStyle(Color.atlasMuted) }.font(.system(size: 9, weight: .semibold)) }
}
struct MetricCard: View {
    var title, value, detail, icon: String; var color: Color
    var body: some View { VStack(alignment: .leading, spacing: 12) { HStack { Text(title).font(.system(size: 8, weight: .bold)).tracking(1.5).foregroundStyle(Color.atlasMuted); Spacer(); Image(systemName: icon).foregroundStyle(color) }; Text(value).font(.system(size: 25, weight: .medium, design: .rounded)).lineLimit(1).minimumScaleFactor(0.65); Text(detail).font(.system(size: 10)).foregroundStyle(.secondary) }.padding(18).frame(maxWidth: .infinity, alignment: .leading).background(Color.atlasPanel, in: RoundedRectangle(cornerRadius: 9)).help(Help.text(title)) }
}

struct FunctionList: View {
    @EnvironmentObject var w: Workspace
    let a: Analysis
    var pseudocode = false
    @State private var query = ""
    var filtered: [BinaryFunction] { a.functions.filter { query.isEmpty || $0.name.localizedCaseInsensitiveContains(query) || $0.address.localizedCaseInsensitiveContains(query) } }
    var body: some View {
        VStack(spacing: 0) {
            HStack { Text("FUNCTIONS").font(.system(size: 9, weight: .bold)).tracking(1.5); Spacer(); Text("\(a.functions.count)").font(.system(size: 9, design: .monospaced)).foregroundStyle(Color.atlasMuted) }.padding(14)
            TextField("Filter functions", text: $query).help(Help.text("Filter functions")).textFieldStyle(.roundedBorder).font(.system(size: 11)).padding(.horizontal, 10).padding(.bottom, 8)
            List(selection: Binding(get: { pseudocode ? w.decompilerFunction?.name ?? "" : w.selectedFunction }, set: { w.selectFunction($0, pseudocode: pseudocode) })) {
                if !pseudocode { Text("All instructions").font(.system(size: 11)).tag("").help("Show every decoded instruction across executable sections.") }
                ForEach(filtered) { function in VStack(alignment: .leading, spacing: 4) { Text(function.name).font(.system(size: 11, weight: .medium, design: .monospaced)).lineLimit(1); Text("\(function.address)  ·  \(function.count)").font(.system(size: 9, design: .monospaced)).foregroundStyle(Color.atlasMuted) }.padding(.vertical, 3).tag(function.name)
                    .help("\(function.name) · \(function.address)\nName source: \(function.nameSource ?? "symbol"). Original: \(function.originalName ?? function.name).\n\(function.library.map { "Library: " + $0 + "\n" } ?? "")Select and press F2 to rename. \(w.label(function.address).isEmpty ? "" : "Note: " + w.label(function.address))")
                    .contextMenu { Button("Rename function…  F2") { w.beginRename(RenameTarget(functionAddress: function.address)) }; Button("Show pseudocode") { w.showPseudocode(function.address) }; Button("Copy name") { w.copy(function.name) } }
                }
            }.listStyle(.sidebar).scrollContentBackground(.hidden)
        }.background(Color.atlasPanel.opacity(0.3)).frame(minWidth: 200, idealWidth: 230, maxWidth: 320)
    }
}
struct DisassemblyView: View {
    @EnvironmentObject var w: Workspace
    let a: Analysis
    @State private var query = ""
    @State private var showInspector = true
    var visible: [Instruction] { w.selectedInstructions.filter { query.isEmpty || ($0.address + $0.mnemonic + $0.operands).localizedCaseInsensitiveContains(query) } }
    var body: some View {
        if a.instructions.isEmpty { EmptyPanel(icon: "text.alignleft", title: "No disassembly available", detail: a.warnings.joined(separator: "\n")) }
        else {
            HSplitView {
                FunctionList(a: a)
                VStack(spacing: 0) {
                    HStack { FollowCodeToggle(); Image(systemName: "magnifyingglass").foregroundStyle(Color.atlasMuted); TextField("Filter instructions", text: $query).help(Help.text("Filter instructions")).textFieldStyle(.plain); Text("\(visible.count.formatted())").font(.system(size: 10, design: .monospaced)).foregroundStyle(Color.atlasMuted); Button { showInspector.toggle() } label: { Image(systemName: "sidebar.right") }.buttonStyle(.plain).help("Show or hide instruction bytes, references, names and annotation controls.") }.padding(12)
                    Divider().opacity(0.3)
                    ScrollViewReader { proxy in
                        ScrollView([.vertical, .horizontal]) {
                            LazyVStack(alignment: .leading, spacing: 0) {
                                ForEach(visible) { ins in
                                    Button { w.selectDecompilerAddress(ins.address) } label: { instructionRow(ins) }.buttonStyle(.plain).id(ins.address)
                                        .contextMenu {
                                            Button("Rename function / linked variable…  F2") { w.beginRename(instruction: ins.address) }
                                            Button("Show linked pseudocode") { w.showPseudocode(ins.address) }.help(Help.text("Show linked pseudocode"))
                                            Button("Follow direct target") { if !ins.target.isEmpty { w.navigate(ins.target) } }.help(Help.text("Follow direct target")).disabled(ins.target.isEmpty)
                                            Button("Copy instruction") { w.copy("\(ins.address)  \(ins.mnemonic) \(ins.operands)") }.help(Help.text("Copy instruction"))
                                            Button("Show bytes") { w.showBytes(ins.offset) }.help(Help.text("Show bytes")).disabled(ins.offset < 0)
                                            Button("Add breakpoint") { w.debugAction("breakpoint", ["spec": ins.address]) }.help(Help.text("Add breakpoint")).disabled(!w.debugStarted)
                                            Button("Bookmark") { w.setAnnotation(address: ins.address, label: w.label(ins.address), comment: w.annotations.first { $0.address == ins.address }?.comment ?? "", bookmark: true) }.help(Help.text("Bookmark"))
                                        }
                                }
                            }.frame(minWidth: 610, alignment: .leading).padding(.vertical, 8)
                        }.onChange(of: w.selectedAddress) { _, value in proxy.scrollTo(value, anchor: .center) }
                        .onChange(of: w.selectedFunction) { _, _ in if let first = w.selectedInstructions.first { proxy.scrollTo(first.address, anchor: .top) } }
                    }
                    HStack { Text("\(w.selectedFunction.isEmpty ? "All executable sections" : w.selectedFunction)"); Spacer(); Text("DIRECT REFERENCES ONLY") }.font(.system(size: 9, design: .monospaced)).foregroundStyle(Color.atlasMuted).padding(10).background(Color.atlasPanel)
                }.frame(minWidth: 430)
                if showInspector { InstructionInspector(a: a).frame(minWidth: 205, idealWidth: 230, maxWidth: 320) }
            }
        }
    }
    func instructionRow(_ i: Instruction) -> some View {
        HStack(spacing: 13) {
            Circle().fill(w.annotations.contains { $0.address == i.address && $0.bookmark } ? Color.atlasGold : .clear).frame(width: 5, height: 5)
            Text(i.address.replacingOccurrences(of: "0x", with: "")).help("Static virtual address of this instruction: " + i.address).foregroundStyle(Color.atlasMuted).frame(width: 108, alignment: .leading)
            Text(i.offset >= 0 ? hex(i.offset) : "—").help("Exact file offset for this instruction. A dash means no file mapping was proved.").foregroundStyle(Color.atlasAccent.opacity(0.75)).frame(width: 82, alignment: .leading)
            Text(i.mnemonic).help("Decoded machine operation: " + i.mnemonic + ". Classification: " + i.kind).foregroundStyle(i.kind == "call" ? Color.atlasAccent : (i.kind == "branch" || i.kind == "jump" ? Color.atlasGold : Color(red: 0.75, green: 0.78, blue: 0.86))).frame(width: 65, alignment: .leading)
            Text(w.displayOperands(i)).help("\(w.displayOperands(i))\nOperands identify registers, immediates, memory locations or branch destinations. Select this instruction and press F2 to name a linked recovered value.").foregroundStyle(Color.white.opacity(0.78)).lineLimit(1)
            if !w.label(i.address).isEmpty { Text("; \(w.label(i.address))").foregroundStyle(Color.atlasAccent) }
            Spacer(minLength: 18)
        }.font(.system(size: 11, design: .monospaced)).padding(.horizontal, 12).frame(height: 25).background(w.selectedAddress == i.address ? Color.atlasAccent.opacity(0.1) : .clear).contentShape(Rectangle())
    }
}
struct InstructionInspector: View {
    @EnvironmentObject var w: Workspace
    let a: Analysis
    var ins: Instruction? { w.codeIndex.instructionsByAddress[w.selectedAddress] }
    var refs: [Reference] { w.codeIndex.referencesByAddress[w.selectedAddress] ?? [] }
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                Text("INSPECTOR").font(.system(size: 9, weight: .bold)).tracking(1.5).foregroundStyle(Color.atlasMuted)
                Text(w.selectedAddress.isEmpty ? "Select an instruction" : w.selectedAddress).font(.system(size: 15, design: .monospaced)).foregroundStyle(Color.atlasAccent).textSelection(.enabled)
                if let ins {
                    Text(ins.mnemonic + " " + ins.operands).font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                    Divider()
                    Text("FILE OFFSET").font(.system(size: 8, weight: .bold)).tracking(1).foregroundStyle(Color.atlasMuted)
                    Text(ins.offset >= 0 ? hex(ins.offset) : "Not mapped").font(.system(size: 11, design: .monospaced))
                    HStack { Button("Hex / patch") { w.showBytes(ins.offset) }.help(Help.text("Hex / patch")).disabled(ins.offset < 0); Button("Pseudocode") { w.showPseudocode(ins.address) } }.font(.caption)
                    Text(ins.bytes).help("Exact original instruction bytes, in file order.").font(.system(size: 10, design: .monospaced)).foregroundStyle(.secondary).textSelection(.enabled)
                    Divider()
                    Text("CROSS REFERENCES").font(.system(size: 8, weight: .bold)).tracking(1).foregroundStyle(Color.atlasMuted)
                    if refs.isEmpty { Text("No direct references").font(.caption).foregroundStyle(.secondary) }
                    ForEach(refs) { ref in Button { w.navigate(ref.source == w.selectedAddress ? ref.target : ref.source) } label: { VStack(alignment: .leading, spacing: 4) { Text(ref.source == w.selectedAddress ? "→ \(ref.target)" : "← \(ref.source)"); Text(ref.kind).foregroundStyle(.secondary) }.font(.system(size: 10, design: .monospaced)) }.buttonStyle(.plain).foregroundStyle(Color.atlasAccent) }
                    Divider()
                    Button("Rename…  F2") { w.beginRename(instruction: ins.address) }.help("Rename this function or a recovered variable linked to the selected instruction.")
                    Button("Annotate this address") { w.page = "Notes" }.help(Help.text("Annotate this address")).buttonStyle(.bordered)
                    if let note = w.annotations.first(where: { $0.address == w.selectedAddress }) { Text(note.label).font(.headline); Text(note.comment).font(.caption).foregroundStyle(.secondary) }
                }
            }.padding(16).frame(maxWidth: .infinity, alignment: .leading)
        }.background(Color.atlasPanel.opacity(0.4))
    }
}
struct SectionsView: View {
    @EnvironmentObject var w: Workspace
    let a: Analysis
    @State private var regions = false
    var rows: [BinarySection] { (regions ? a.regions : a.sections).filter { w.filter.isEmpty || $0.name.localizedCaseInsensitiveContains(w.filter) } }
    var body: some View {
        VStack(spacing: 0) {
            HStack { Picker("View", selection: $regions) { Text("Sections").tag(false); Text("Segments / mappings").tag(true) }.help(Help.text("View")).pickerStyle(.segmented).frame(width: 300); Spacer(); Text("Right-click a name to navigate").font(.caption).foregroundStyle(.secondary) }.padding(14)
            FilterBar(text: $w.filter, count: rows.count)
            Table(rows) {
                TableColumn("Name") { s in Text(s.name).font(.system(size: 11, design: .monospaced)).contextMenu { Button("Show bytes") { w.showBytes(s.offset) }.help(Help.text("Show bytes")); Button("Disassemble address") { w.navigate(s.address) }.help(Help.text("Disassemble address")); Button("Copy address") { w.copy(s.address) }.help(Help.text("Copy address")) } }.width(min: 180, ideal: 230)
                TableColumn("Virtual address") { Text($0.address).help("Static virtual address in the binary image. The runtime address may include a load slide.") }.width(min: 110, ideal: 140)
                TableColumn("File offset") { Text(hex($0.offset)) .help("Byte position measured from the beginning of the complete file. Use this value for raw hex navigation and patching.") }.width(90)
                TableColumn("File size") { Text(humanSize($0.size)) .help("Number of bytes stored on disk for this range. Zero-filled data may have a larger memory size.") }.width(95)
                TableColumn("Memory size") { Text(humanSize($0.virtualSize)) .help("Number of bytes reserved in memory, including any zero-filled tail that has no file bytes.") }.width(100)
                TableColumn("Permissions") { Text($0.flags).help("Read, write and execute flags recorded for this section or memory mapping.") }.width(80)
                TableColumn("Entropy") { s in HStack { Text(String(format: "%.2f", s.entropy)); Capsule().fill(s.entropy > 7.2 ? Color.atlasGold : .atlasAccent).frame(width: CGFloat(s.entropy * 6), height: 4) } .help("Shannon byte entropy from 0 to 8 bits per byte. A high value may reflect compressed or encrypted data.") }.width(min: 100, ideal: 110)
            }.font(.system(size: 11, design: .monospaced))
        }
    }
}
struct SymbolsView: View {
    @EnvironmentObject var w: Workspace
    let symbols: [BinarySymbol]
    var rows: [BinarySymbol] { symbols.filter { w.filter.isEmpty || ($0.name + $0.address + $0.library).localizedCaseInsensitiveContains(w.filter) } }
    var body: some View {
        VStack(spacing: 0) {
            FilterBar(text: $w.filter, placeholder: "Filter names, addresses or libraries", count: rows.count)
            Table(rows) {
                TableColumn("Symbol") { s in Text(s.name).contextMenu { Button("Go to address") { w.navigate(s.address) }.help(Help.text("Go to address")); Button("Copy symbol") { w.copy(s.name) }.help(Help.text("Copy symbol")); Button("Set breakpoint") { w.debugAction("breakpoint", ["spec": s.name]) }.help(Help.text("Set breakpoint")).disabled(!w.debugStarted) } }.width(min: 210, ideal: 310)
                TableColumn("Address") { Text($0.address).help("Static virtual address associated with this symbol. Undefined imports may not have a resolved code address.") }.width(min: 115, ideal: 140)
                TableColumn("Kind") { StatusPill(text: $0.kind, color: $0.kind == "import" ? .atlasGold : .atlasAccent) .help("How the parser classified this symbol, such as function, import, export or stub.") }.width(90)
                TableColumn("Size") { Text($0.size == 0 ? "—" : String($0.size)) .help("Symbol size in bytes when recorded. A dash means no size was supplied, not that the function is empty.") }.width(70)
                TableColumn("Library / forwarder") { Text($0.library).help("Dependency supplying an import, or the target of a forwarded export, when recorded in metadata.") }.width(min: 170, ideal: 300)
            }.font(.system(size: 11, design: .monospaced))
        }
    }
}
struct ImportsView: View {
    let a: Analysis
    @State private var exports = false
    var body: some View { VStack(spacing: 0) { Picker("Table", selection: $exports) { Text("Imports (\(a.imports.count))").tag(false); Text("Exports (\(a.exports.count))").tag(true) }.help(Help.text("Table")).pickerStyle(.segmented).frame(width: 320).padding(14); SymbolsView(symbols: exports ? a.exports : a.imports) } }
}
struct StringsView: View {
    @EnvironmentObject var w: Workspace
    let a: Analysis
    @State private var encoding = "All"
    var rows: [BinaryString] { a.strings.filter { (encoding == "All" || $0.encoding == encoding) && (w.filter.isEmpty || $0.value.localizedCaseInsensitiveContains(w.filter)) } }
    var body: some View {
        VStack(spacing: 0) {
            HStack { FilterBar(text: $w.filter, placeholder: "Filter extracted strings", count: rows.count); Picker("Encoding", selection: $encoding) { ForEach(["All", "ASCII", "UTF-16LE", "UTF-16BE"], id: \.self) { Text($0) } }.help(Help.text("Encoding")).frame(width: 170).padding(.trailing, 12) }
            Table(rows) {
                TableColumn("File offset") { s in Text(hex(s.offset)).contextMenu { Button("Show bytes") { w.showBytes(s.offset) }.help(Help.text("Show bytes")) } }.width(100)
                TableColumn("Virtual address") { Text($0.address).help("Static virtual address in the binary image. The runtime address may include a load slide.") }.width(125)
                TableColumn("Encoding") { Text($0.encoding).help("Encoding used to decode this text from file bytes: ASCII, UTF-16LE or UTF-16BE.") }.width(85)
                TableColumn("String") { s in Text(s.value).lineLimit(1).contextMenu { Button("Copy string") { w.copy(s.value) }.help(Help.text("Copy string")); Button("Show bytes") { w.showBytes(s.offset) }.help(Help.text("Show bytes")); Button("Go to VA") { w.navigate(s.address) }.help(Help.text("Go to VA")).disabled(s.address.isEmpty) } }.width(min: 400, ideal: 750)
            }.font(.system(size: 11, design: .monospaced))
        }
    }
}
struct HexView: View {
    @EnvironmentObject var w: Workspace
    let a: Analysis
    @State private var offset = "0x0"
    @State private var text = ""
    @State private var patchBytes = ""
    @State private var busy = false
    @State private var patchStatus = ""
    var body: some View {
        VStack(spacing: 0) {
            if !w.hexContext.isEmpty { HStack { Label(w.hexContext, systemImage: "link").font(.system(size: 11, design: .monospaced)); Spacer(); Button("Back to Pseudocode") { w.page = "Decompiler" }.help(Help.text("Back to Pseudocode")) }.padding(14).background(Color.atlasAccent.opacity(0.08)) }
            HStack { Text("File offset").foregroundStyle(.secondary); TextField("0x0", text: $offset).help(Help.text("0x0")).font(.system(size: 12, design: .monospaced)).frame(width: 150).onSubmit { load() }; Button("Read") { load() }.help(Help.text("Read")); Button { move(-512) } label: { Image(systemName: "chevron.left") }.help("Read the previous 512-byte file page."); Button { move(512) } label: { Image(systemName: "chevron.right") }.help("Read the next 512-byte file page."); Spacer(); Text("512 bytes / page").font(.caption).foregroundStyle(Color.atlasMuted) }.padding(16).disabled(busy)
            Divider().opacity(0.4)
            MonoText(text: text)
            Divider().opacity(0.4)
            VStack(alignment: .leading, spacing: 12) {
                HStack { Text("PATCH TO A NEW FILE").font(.system(size: 9, weight: .bold)).tracking(1.4); Spacer(); if !patchStatus.isEmpty { Text(patchStatus).font(.caption).foregroundStyle(Color.atlasAccent) } }
                HStack { TextField("Replacement hex bytes, starting at the file offset above: 90 90", text: $patchBytes).help(Help.text("Replacement hex bytes, starting at the file offset above: 90 90")).font(.system(size: 12, design: .monospaced)); Button("Save patched copy…") { savePatch() }.help(Help.text("Save patched copy…")).disabled(patchBytes.isEmpty || busy) }
                Text("Same-length replacement. The original is preserved. Patches may invalidate signatures or checksums.").font(.system(size: 10)).foregroundStyle(.secondary)
            }.padding(20).background(Color.atlasPanel)
        }.task { offset = hex(w.hexOffset); patchBytes = w.hexSelectionBytes; load() }
    }
    func move(_ delta: Int) { let current = Int(addressValue(offset) ?? 0); offset = hex(max(0, min(max(0, a.size - 1), current + delta))); load() }
    func load() {
        guard let raw = addressValue(offset), raw <= UInt64(Int.max) else { w.error = "Invalid file offset"; return }
        busy = true
        Task { do { let result = try await EngineClient.request(["action": "hex", "path": a.path, "offset": Int(raw), "count": 512], as: HexResult.self); text = result.text; w.hexOffset = Int(raw) } catch { w.error = error.localizedDescription }; busy = false }
    }
    func savePatch() {
        guard let raw = addressValue(offset), raw <= UInt64(Int.max) else { w.error = "Invalid file offset"; return }
        let panel = NSSavePanel(); panel.nameFieldStringValue = a.name + ".patched"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        busy = true
        Task { do { let result = try await EngineClient.request(["action": "patch", "path": a.path, "output": url.path, "offset": Int(raw), "bytes": patchBytes, "sha256": a.sha256], as: PatchResult.self); patchStatus = "Saved \(result.count) patched bytes"; w.status = "Patched copy: \(result.path)" } catch { w.error = error.localizedDescription }; busy = false }
    }
}
struct SearchView: View {
    @EnvironmentObject var w: Workspace
    let a: Analysis
    @State private var query = ""
    @State private var mode = "text"
    @State private var result: SearchResult?
    @State private var busy = false
    var body: some View {
        VStack(spacing: 0) {
            HStack { Picker("Mode", selection: $mode) { Text("UTF-8 text").tag("text"); Text("UTF-16LE").tag("utf16"); Text("Hex + wildcards").tag("hex") }.help(Help.text("Mode")).frame(width: 190); TextField(mode == "hex" ? "48 8B ?? FF" : "Search the entire file", text: $query).help("Enter text or space-separated hex byte pairs. In hex mode, ?? matches any one byte. Press Return to search the whole file.").onSubmit { search() }; Button("Search") { search() }.help(Help.text("Search")).buttonStyle(.borderedProminent).disabled(query.isEmpty || busy); if busy { ProgressView().controlSize(.small) } }.padding(16)
            if let result {
                HStack { Text("\(result.hits.count.formatted()) matches\(result.truncated ? " · limit reached" : "")"); Spacer(); Text("Right-click an offset to inspect bytes") }.font(.caption).foregroundStyle(.secondary).padding(.horizontal, 18).padding(.bottom, 12)
                Table(result.hits) { TableColumn("File offset") { h in Text(hex(h.offset)).contextMenu { Button("Show bytes") { w.showBytes(h.offset) }.help(Help.text("Show bytes")); Button("Copy offset") { w.copy(hex(h.offset)) }.help(Help.text("Copy offset")) } }.width(140); TableColumn("Bytes at match") { Text($0.bytes).help("File bytes beginning at this search match. Offsets refer to the original file.") } }.font(.system(size: 11, design: .monospaced))
            } else { EmptyPanel(icon: "magnifyingglass", title: "Search bytes, text, and patterns", detail: "Hex patterns accept ?? for any byte. Searches include overlapping matches and all file data.") }
        }
    }
    func search() { busy = true; Task { do { result = try await EngineClient.request(["action": "search", "path": a.path, "query": query, "mode": mode], as: SearchResult.self) } catch { w.error = error.localizedDescription }; busy = false } }
}
struct CompareView: View {
    @EnvironmentObject var w: Workspace
    let a: Analysis
    @State private var other = ""
    @State private var result: DiffResult?
    @State private var busy = false
    var body: some View {
        VStack(spacing: 0) {
            HStack { VStack(alignment: .leading, spacing: 5) { Text("BASE  \(a.name)").font(.system(size: 10, weight: .semibold, design: .monospaced)).foregroundStyle(Color.atlasMuted); Text(other.isEmpty ? "Select another binary for byte-by-byte comparison" : other).font(.system(size: 11)).lineLimit(1) }; Spacer(); Button("Choose comparison file…") { choose() }.help(Help.text("Choose comparison file…")).disabled(busy); if busy { ProgressView().controlSize(.small) } }.padding(18)
            if let result {
                HStack { StatusPill(text: result.changed == 0 ? "IDENTICAL" : "\(result.changed.formatted()) CHANGED BYTES", color: result.changed == 0 ? .atlasAccent : .atlasGold); Text("\(humanSize(result.leftSize)) → \(humanSize(result.rightSize))\(result.truncated ? " · range limit reached" : "")").font(.caption).foregroundStyle(.secondary); Spacer() }.padding(.horizontal, 18).padding(.bottom, 16)
                Table(result.runs) {
                    TableColumn("Offset") { r in Text(hex(r.offset)).contextMenu { Button("Show original bytes") { w.showBytes(r.offset) }.help(Help.text("Show original bytes")) } }.width(110)
                    TableColumn("Length") { Text(String($0.size)) .help("Number of bytes in this contiguous difference, including added or removed bytes at the file tail.") }.width(80)
                    TableColumn("Original (first 32 bytes)") { Text($0.before).help("Preview of bytes from the loaded binary in this changed range. The length column gives the full range size.") }
                    TableColumn("Comparison (first 32 bytes)") { Text($0.after).help("Preview from the comparison file at the corresponding offset. Missing tails appear as absent bytes.") }
                }.font(.system(size: 10, design: .monospaced))
            } else { EmptyPanel(icon: "square.split.2x1", title: "Inspect binary changes", detail: "Compare corresponding file offsets, including added or removed tails. This view compares bytes; it does not match functions semantically.") }
        }
    }
    func choose() {
        let panel = NSOpenPanel(); guard panel.runModal() == .OK, let url = panel.url else { return }; other = url.path; busy = true
        Task { do { result = try await EngineClient.request(["action": "compare", "path": a.path, "other": other], as: DiffResult.self) } catch { w.error = error.localizedDescription }; busy = false }
    }
}
struct NotesView: View {
    @EnvironmentObject var w: Workspace
    @State private var address = ""
    @State private var label = ""
    @State private var comment = ""
    @State private var bookmark = true
    @State private var selectedNote: String?
    var body: some View {
        HSplitView {
            VStack(alignment: .leading, spacing: 15) {
                Text("ADDRESS ANNOTATION").font(.system(size: 9, weight: .bold)).tracking(1.5).foregroundStyle(Color.atlasMuted)
                TextField("Virtual address (hex)", text: $address).help(Help.text("Virtual address (hex)")).font(.system(size: 13, design: .monospaced)).onSubmit { load(address) }
                TextField("Custom label", text: $label).help(Help.text("Custom label"))
                Toggle("Bookmark this address", isOn: $bookmark).help(Help.text("Bookmark this address"))
                TextEditor(text: $comment).help("Free-form analyst comment for this static address. Apply annotation, then save the project to retain your notes.").font(.system(size: 12)).frame(minHeight: 150).scrollContentBackground(.hidden).padding(8).background(Color.atlasPanel, in: RoundedRectangle(cornerRadius: 6))
                HStack { Button("Apply annotation") { w.setAnnotation(address: address, label: label, comment: comment, bookmark: bookmark) }.help(Help.text("Apply annotation")).buttonStyle(.borderedProminent); Button("Save project…") { w.saveProject() }.help(Help.text("Save project…")) }
                Text("Projects preserve labels, comments and bookmarks alongside the binary's SHA-256 identity.").font(.system(size: 11)).foregroundStyle(.secondary)
            }.padding(22).frame(minWidth: 370, maxWidth: 540)
            List(selection: $selectedNote) {
                if w.annotations.isEmpty { Text("No annotations yet").foregroundStyle(.secondary) }
                ForEach(w.annotations) { note in
                    VStack(alignment: .leading, spacing: 8) { HStack { Image(systemName: note.bookmark ? "bookmark.fill" : "text.bubble").foregroundStyle(Color.atlasGold); Text(note.address).font(.system(size: 11, design: .monospaced)); Text(note.label).font(.system(size: 12, weight: .semibold)) }; Text(note.comment).font(.system(size: 11)).foregroundStyle(.secondary).lineLimit(3) }.padding(.vertical, 8).frame(maxWidth: .infinity, alignment: .leading) .tag(note.address).contextMenu { Button("Go to code") { w.navigate(note.address) }.help(Help.text("Go to code")); Button("Delete", role: .destructive) { w.annotations.removeAll { $0.id == note.id }; w.dirty = true }.help(Help.text("Delete")) }
                }
            }.scrollContentBackground(.hidden)
        }.onAppear { load(w.selectedAddress) }.onChange(of: selectedNote) { _, value in if let value { load(value) } }
    }
    func load(_ value: String) { address = value; let n = w.annotations.first { $0.address == value }; label = n?.label ?? ""; comment = n?.comment ?? ""; bookmark = n?.bookmark ?? true }
}
