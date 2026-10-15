import SwiftUI

struct FollowCodeToggle: View {
    @EnvironmentObject var w: Workspace
    var body: some View {
        Toggle(isOn: Binding(get: { w.followCode }, set: { w.setFollowCode($0) })) {
            Label(w.followCode ? "Follow on" : "Follow off", systemImage: w.followCode ? "link" : "link.badge.plus")
        }.toggleStyle(.button).font(.system(size: 10)).help("Follow on: selecting a function, instruction or pseudocode line moves the other code view. Follow off: each view keeps its own function, selection and scroll position. Explicit jump commands still navigate.")
    }
}

struct RenameSheet: View {
    @EnvironmentObject var w: Workspace
    @Environment(\.dismiss) var dismiss
    let context: RenameContext
    @State private var selected = ""
    @State private var name = ""
    @FocusState private var focused: Bool
    var variable: RecoveredVariable? { context.variables.first { $0.name == selected } }
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Rename selected name").font(.title2)
            Text("\(context.function.name) · \(context.function.address)").font(.system(size: 11, design: .monospaced)).foregroundStyle(Color.atlasAccent)
            Picker("Name", selection: $selected) {
                Text("Function · \(context.function.name)").tag("")
                ForEach(context.variables) { v in
                    Text("\(v.addresses.contains(context.instruction) ? "↳ " : "")\(v.displayName) · \(v.type) · \(v.storage)").tag(v.name)
                }
            }.help("Choose the function or a recovered variable. The arrow marks values linked to the selected instruction; a register can represent several values over time.")
            if !context.instruction.isEmpty {
                Text("↳ Linked to instruction \(context.instruction). Other recovered values are available below them.").font(.caption).foregroundStyle(.secondary)
            }
            TextField("New C identifier", text: $name).focused($focused).onSubmit { apply() }
                .help("Enter a unique C identifier, up to 80 characters. The name is shared by code views and saved in the analysis project. Machine bytes and storage identities stay the same.")
            Text(variable.map { "Storage: \($0.name) · \($0.storage) · \($0.type)" } ?? "Original name: \(context.function.originalName ?? context.function.name) · source: \(context.function.nameSource ?? "symbol")")
                .font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary).textSelection(.enabled)
                .help("Original evidence remains available after a rename. Variable types reflect machine width; they are not proven source-level types.")
            if !w.renameError.isEmpty { Text(w.renameError).font(.callout).foregroundStyle(Color.atlasGold).fixedSize(horizontal: false, vertical: true) }
            HStack {
                Button("Reset name") { w.commitRename(context, variable: selected, name: "", reset: true) }.disabled(w.renameBusy)
                    .help("Remove this analyst override and restore the symbol, signature or generated variable name.")
                Spacer()
                if w.renameBusy { ProgressView().controlSize(.small) }
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction).disabled(w.renameBusy).help("Close without changing this name.")
                Button("Rename") { apply() }.keyboardShortcut(.defaultAction).disabled(name.isEmpty || w.renameBusy).help("Validate and apply the name to all uses in this function, or all known calls to the renamed function. Save the project with Command-S.")
            }
        }.padding(24).frame(width: 640)
            .onAppear { selected = context.selected; updateName(); focused = true }
            .onChange(of: selected) { _, _ in updateName() }
            .interactiveDismissDisabled(w.renameBusy)
    }
    func updateName() { name = variable?.displayName ?? context.function.name }
    func apply() { if !name.isEmpty && !w.renameBusy { w.commitRename(context, variable: selected, name: name) } }
}

/// Attributed links give per-identifier hit testing and accessibility without making the line editable text.
struct SelectableCodeLine: View {
    @EnvironmentObject var w: Workspace
    let line: PseudocodeLine
    let result: Decompilation
    let wrap: Bool
    private static let identifierPattern = try! NSRegularExpression(pattern: "\\b[A-Za-z_][A-Za-z0-9_]*\\b")
    private static let excludedPattern = try! NSRegularExpression(pattern: #""(?:\\.|[^"\\])*"|/\*.*?\*/|//.*$"#)
    var targets: [(String, RenameTarget)] { w.codeNames.targets }
    var attributed: AttributedString {
        var text = coloredCode(line)
        guard !["comment", "mechanic"].contains(line.kind) else { return text }
        let names = targets
        // Comments and string literals are not rename targets.
        let excluded = Self.excludedPattern.matches(in: line.text, range: NSRange(line.text.startIndex..., in: line.text)).map(\.range)
        for match in Self.identifierPattern.matches(in: line.text, range: NSRange(line.text.startIndex..., in: line.text)) {
            guard !excluded.contains(where: { NSIntersectionRange($0, match.range).length > 0 }), let range = Range(match.range, in: line.text),
                  let index = w.codeNames.byName[String(line.text[range])],
                  let lower = AttributedString.Index(range.lowerBound, within: text), let upper = AttributedString.Index(range.upperBound, within: text) else { continue }
            text[lower..<upper].link = URL(string: "asteria://name/\(index)")
            if w.renameTarget == names[index].1 { text[lower..<upper].backgroundColor = Color.atlasGold.opacity(0.3) }
        }
        return text
    }
    var body: some View {
        Text(attributed).fixedSize(horizontal: !wrap, vertical: true)
            .environment(\.openURL, OpenURLAction { url in
                if let index = Int(url.lastPathComponent), targets.indices.contains(index) {
                    w.selectPseudocode(line); w.renameTarget = targets[index].1
                    w.status = "Selected \(targets[index].0) · F2 to rename"
                }
                return .handled
            })
            .help("\(line.explanation)\nClick a variable or function name to highlight it, then press F2 to rename. Click the line number to select all contributing instructions.")
    }
}

struct RecognitionView: View {
    @EnvironmentObject var w: Workspace
    let a: Analysis
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                HStack {
                    Text("Atlas library recognition").font(.title2)
                    Spacer()
                    Button("Import pack…") { w.importSignatures() }.help("Install an .atlas.json pack in Application Support/Asteria/Signatures. Installed packs are applied automatically when opening binaries. IDA .sig files are not supported.")
                    Button("Learn / export…") { w.exportSignatures() }.help("Learn complete instruction fingerprints from eligible named functions in this binary. Export a portable .atlas.json pack, then import it to recognize matching stripped builds.")
                    Button("Rescan") { w.refreshRecognition() }.help("Reload installed signature packs and match this binary again, preserving analyst names and notes.")
                }
                Text("Automatic names come from symbols, imports and Atlas signatures. Atlas checks whole learned instruction bodies, branch structure and named call references. Ambiguous fingerprints stay unnamed.").font(.callout).foregroundStyle(.secondary)
                if let r = a.recognition {
                    HStack(spacing: 18) {
                        StatusPill(text: "\(r.signatures) SIGNATURES", color: .atlasAccent).help("Total entries in the loaded packs. Only entries for this architecture and bit width are considered.")
                        StatusPill(text: "\(r.matches.filter { $0.applied }.count) NAMES APPLIED", color: .atlasAccent).help("Matches that supplied a name to a previously unnamed function. Existing symbol and analyst names take precedence.")
                        StatusPill(text: "\(r.ambiguities.count) AMBIGUOUS", color: .atlasGold).help("Different names matched the same body. No candidate was chosen automatically.")
                    }
                    Text("Loaded libraries").font(.headline)
                    ForEach(Array(r.libraries.enumerated()), id: \.offset) { _, library in Text(library).font(.system(size: 11, design: .monospaced)).help("Library label supplied by this signature pack. A match establishes a code fingerprint, not the binary's publisher or trustworthiness.") }
                    Text("Matches").font(.headline)
                    if r.matches.isEmpty { Text("No matches in the installed packs. Symbol names are still used. Learn a pack from a matching named build to extend coverage.").foregroundStyle(.secondary).font(.callout) }
                    ForEach(r.matches) { match in
                        Button { w.navigate(match.address) } label: {
                            HStack { Text(match.address).foregroundStyle(Color.atlasAccent).frame(width: 120, alignment: .leading); Text(match.name).frame(width: 180, alignment: .leading); Text(match.library).foregroundStyle(.secondary); Spacer(); Text(match.applied ? "Applied" : "Symbol retained"); Text("\(match.size) bytes") }
                                .font(.system(size: 11, design: .monospaced)).padding(10).background(Color.atlasPanel, in: RoundedRectangle(cornerRadius: 5))
                        }.buttonStyle(.plain).help("Matched all \(match.instructions) instructions (\(match.size) bytes). Click to inspect the evidence in disassembly. Existing symbol names are retained even when a signature also matches.")
                    }
                    ForEach(r.ambiguities) { item in Label("\(item.address) · \(item.names.joined(separator: ", "))", systemImage: "questionmark.diamond").font(.system(size: 11, design: .monospaced)).foregroundStyle(Color.atlasGold).help("These candidate names share a matching fingerprint. Inspect the function and rename it manually with F2 if other evidence resolves the collision.") }
                    ForEach(r.warnings, id: \.self) { warning in Label(warning, systemImage: "exclamationmark.triangle").font(.callout).foregroundStyle(Color.atlasGold).help("This pack could not be loaded. Check its schema, size and entry limits before importing it again.") }
                }
                Text("The bundled pack covers Asteria's reference C memory/string routines across selected Clang builds. Compiler version, optimization and implementation differences can prevent matches. Add packs for the libraries you use; Atlas does not include IDA's signature database.").font(.caption).foregroundStyle(.secondary)
            }.padding(24)
        }
    }
}
