import AppKit
import SwiftUI

extension Color {
    static let atlasBackground = Color(red: 0.055, green: 0.068, blue: 0.085)
    static let atlasPanel = Color(red: 0.083, green: 0.099, blue: 0.121)
    static let atlasAccent = Color(red: 0.46, green: 0.87, blue: 0.76)
    static let atlasGold = Color(red: 0.96, green: 0.71, blue: 0.40)
    static let atlasMuted = Color(red: 0.48, green: 0.56, blue: 0.65)
}

@main struct AsteriaApp: App {
    @StateObject private var workspace = Workspace()
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    var body: some Scene {
        WindowGroup {
            Workbench().environmentObject(workspace)
                .frame(minWidth: 1080, minHeight: 720)
                .preferredColorScheme(.dark)
                .tint(.atlasAccent)
                .onAppear { delegate.workspace = workspace; NSApp.setActivationPolicy(.regular); NSApp.activate(ignoringOtherApps: true) }
                .onOpenURL { url in if url.lastPathComponent.hasSuffix(".asteria.json") { workspace.loadProject(url) } else { workspace.open(url) } }
        }
        .defaultSize(width: 1440, height: 900)
        .windowStyle(.hiddenTitleBar)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("Open Binary…") { workspace.openPanel() }.keyboardShortcut("o")
                Button("Open Project…") { workspace.openPanel(project: true) }.keyboardShortcut("o", modifiers: [.command, .shift])
                Button("Open Training Binary") { workspace.openSample() }
            }
            CommandGroup(replacing: .saveItem) {
                Button("Save Analysis Project…") { workspace.saveProject() }.keyboardShortcut("s").disabled(workspace.analysis == nil)
                Button("Export Markdown Report…") { workspace.exportReport() }
                Button("Export Full Analysis JSON…") { workspace.exportReport(json: true) }
            }
            CommandMenu("Analysis") {
                Button("Static Workspace") { workspace.mode = "Static" }.keyboardShortcut("1")
                Button("Dynamic Workspace") { workspace.mode = "Dynamic" }.keyboardShortcut("2")
                Button("Disassembly") { workspace.mode = "Static"; workspace.page = "Disassembly" }.help(Help.text("Disassembly")).keyboardShortcut("d")
                Button("Pseudocode") { workspace.showPseudocode() }.keyboardShortcut("p", modifiers: [.command, .shift]).disabled(workspace.analysis == nil)
                Toggle("Code Views Follow Each Other", isOn: Binding(get: { workspace.followCode }, set: { workspace.setFollowCode($0) }))
                Button("Rename Selection…") { workspace.beginRename() }.keyboardShortcut(KeyEquivalent("\u{F705}"), modifiers: []).disabled(workspace.analysis == nil || workspace.renameBusy)
                Button("Library Recognition") { workspace.mode = "Static"; workspace.page = "Library Recognition" }.help(Help.text("Library Recognition")).disabled(workspace.analysis == nil)
                Button("Control Flow Graph") { workspace.mode = "Static"; workspace.page = "Control Flow" }.keyboardShortcut("g", modifiers: [.command, .shift])
                Button("Continue") { workspace.debugAction("continue") }.keyboardShortcut(KeyEquivalent("\u{F708}"), modifiers: []).disabled(!workspace.debug.stopped)
                Button("Step Over Instruction") { workspace.debugAction("instructionOver") }.keyboardShortcut(KeyEquivalent("\u{F709}"), modifiers: []).disabled(!workspace.debug.stopped)
                Button("Step Into Instruction") { workspace.debugAction("instructionInto") }.keyboardShortcut(KeyEquivalent("\u{F70A}"), modifiers: []).disabled(!workspace.debug.stopped)
                Button("Step Out") { workspace.debugAction("stepOut") }.keyboardShortcut(KeyEquivalent("\u{F70B}"), modifiers: []).disabled(!workspace.debug.stopped)
            }
        }
    }
}
final class AppDelegate: NSObject, NSApplicationDelegate {
    weak var workspace: Workspace?
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        MainActor.assumeIsolated { workspace?.allowReplace() == false ? .terminateCancel : .terminateNow }
    }
    func applicationWillTerminate(_ notification: Notification) { EngineClient.shutdown(); MainActor.assumeIsolated { workspace?.debugger.shutdown() } }
}

struct Workbench: View {
    @EnvironmentObject var w: Workspace
    @State private var jump = ""
    let staticPages: [(String, String)] = [("Overview","square.grid.2x2"),("Disassembly","text.alignleft"),("Decompiler","curlybraces"),("Library Recognition","signature"),("Control Flow","point.3.connected.trianglepath.dotted"),("Sections","square.stack.3d.up"),("Symbols","function"),("Imports & Exports","arrow.left.arrow.right"),("Strings","text.quote"),("Hex & Patch","number.square"),("Search","magnifyingglass"),("Compare","square.split.2x1"),("Notes","bookmark")]
    let dynamicPages: [(String,String)] = [("Session","play.rectangle"),("Breakpoints","stop.circle"),("Threads & Stack","list.bullet.indent"),("Registers","cpu"),("Variables","curlybraces"),("Modules","shippingbox"),("Memory","memorychip"),("Console","terminal")]
    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 16) {
                Image(systemName: "asterisk.circle.fill").font(.system(size: 25, weight: .light)).foregroundStyle(Color.atlasAccent)
                Text("ASTERIA").font(.system(size: 14, weight: .bold, design: .rounded)).tracking(3)
                Rectangle().fill(Color.white.opacity(0.12)).frame(width: 1, height: 22)
                Text(w.analysis?.name ?? "Binary analysis workbench").help(w.analysis?.path ?? "Open a binary to begin static inspection.").font(.system(size: 12, weight: .medium)).lineLimit(1)
                if w.dirty { Circle().fill(Color.atlasGold).frame(width: 6, height: 6).help("This project has unsaved notes, code names or preferences. Press Command-S to save.") }
                Spacer()
                Picker("Workspace", selection: $w.mode) { Text("Static analysis").tag("Static"); Text("Dynamic debugger").tag("Dynamic") }.help(Help.text("Workspace")).pickerStyle(.segmented).labelsHidden().frame(width: 280)
                Button { w.openPanel() } label: { Label("Open", systemImage: "folder") }.help("Open a binary or drop a file into the window. Static inspection reads the file without executing it. Command-O.")
                Menu { Button("Save Project") { w.saveProject() }.help(Help.text("Save Project")); Button("Export Report") { w.exportReport() }.help(Help.text("Export Report")); Button("Export Analysis JSON") { w.exportReport(json: true) }.help(Help.text("Export Analysis JSON")) } label: { Image(systemName: "square.and.arrow.up") }.menuStyle(.borderlessButton).frame(width: 25).help("Save the project or export a Markdown report or complete analysis JSON.")
            }.padding(.leading, 80).padding(.trailing, 20).frame(height: 57).background(Color.atlasPanel)
            Divider().opacity(0.4)
            HSplitView {
                sidebar.frame(minWidth: 190, idealWidth: 208, maxWidth: 260)
                VStack(spacing: 0) {
                    if w.analysis != nil || w.mode == "Dynamic" {
                        HStack {
                            VStack(alignment: .leading, spacing: 4) {
                                Text(w.page).font(.system(size: 22, weight: .semibold))
                                Text(w.mode == "Static" ? "STATIC WORKSPACE  /  \(w.analysis?.arch.uppercased() ?? "")" : "DYNAMIC WORKSPACE  /  LLDB").font(.system(size: 9, weight: .semibold)).tracking(1.5).foregroundStyle(Color.atlasMuted)
                            }
                            Spacer()
                            if w.mode == "Static" {
                                if let a = w.analysis, a.slices.count > 1 {
                                    Picker("Slice", selection: Binding(get: { a.selectedSlice }, set: { value in w.open(URL(fileURLWithPath: a.path), slice: value, preserve: true); w.dirty = true })) {
                                        ForEach(a.slices) { Text($0.arch).tag($0.index) }
                                    }.help(Help.text("Slice")).frame(width: 140)
                                }
                                HStack { Image(systemName: "arrow.turn.down.right").foregroundStyle(Color.atlasMuted); TextField("Jump to VA (hex)", text: $jump).help(Help.text("Jump to VA (hex)")).textFieldStyle(.plain).onSubmit { if addressValue(jump) != nil { w.navigate("0x"+String(addressValue(jump)!,radix:16)) } else { w.error = "Enter a hexadecimal virtual address" } } }.padding(8).frame(width: 188).background(Color.white.opacity(0.04), in: RoundedRectangle(cornerRadius: 6))
                            } else { StatusPill(text: w.debug.state.uppercased(), color: w.debug.stopped ? .atlasGold : .atlasAccent) }
                        }.padding(22)
                        Divider().opacity(0.35)
                    }
                    Group {
                        if w.mode == "Dynamic" { DebugWorkspace() }
                        else if w.analysis == nil { WelcomeView() }
                        else { StaticWorkspace() }
                    }.frame(maxWidth: .infinity, maxHeight: .infinity)
                }.frame(minWidth: 800)
            }
            Divider().opacity(0.4)
            HStack(spacing: 9) {
                Circle().fill(w.loading ? Color.atlasGold : Color.atlasAccent).frame(width: 5, height: 5)
                Text(w.status).lineLimit(1).help(w.status)
                Spacer()
                if let a = w.analysis { Text("\(humanSize(a.size))   ·   \(a.bits)-bit \(a.endian)-endian") }
                Text("ASTERIA 0.3.1").help("Asteria 0.3.1 · original decompiler and Atlas recognition, LLVM disassembly and LLDB debugging.").foregroundStyle(Color.atlasMuted)
            }.font(.system(size: 10, design: .monospaced)).foregroundStyle(Color.secondary).padding(.horizontal, 18).frame(height: 29).background(Color.atlasPanel)
        }.background(Color.atlasBackground)
        .overlay { if w.loading { ZStack { Color.black.opacity(0.45); VStack(spacing: 14) { ProgressView(); Text(w.status).font(.callout); Text("Reading the binary without executing it").font(.caption).foregroundStyle(.secondary); Button("Cancel") { w.cancelAnalysis() }.help("Stop loading this binary and return to the previous workspace.") }.padding(30).background(.ultraThickMaterial, in: RoundedRectangle(cornerRadius: 14)) } } }
        .sheet(item: $w.renameContext) { context in RenameSheet(context: context).environmentObject(w) }
        .alert("Asteria", isPresented: Binding(get: { w.error != nil }, set: { if !$0 { w.error = nil } })) { Button("OK") { w.error = nil } } message: { Text(w.error ?? "") }
        .onChange(of: w.mode) { _, value in if value == "Static" && dynamicPages.contains(where: { $0.0 == w.page }) { w.page = "Overview" }; if value == "Dynamic" && !dynamicPages.contains(where: { $0.0 == w.page }) { w.page = "Session" }; w.filter = "" }
        .onDrop(of: [.fileURL], isTargeted: nil) { providers in
            guard let p = providers.first else { return false }
            _ = p.loadObject(ofClass: URL.self) { url, _ in if let url { Task { @MainActor in w.open(url) } } }
            return true
        }
    }
    var sidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(w.mode == "Static" ? "EXPLORER" : "DEBUGGER").font(.system(size: 9, weight: .bold)).tracking(2).foregroundStyle(Color.atlasMuted).padding(.horizontal, 22).padding(.top, 27).padding(.bottom, 16)
            ForEach(w.mode == "Static" ? staticPages : dynamicPages, id: \.0) { name, icon in
                Button { w.page = name; w.filter = "" } label: {
                    HStack(spacing: 12) {
                        Image(systemName: icon).font(.system(size: 13)).frame(width: 18)
                        Text(name).font(.system(size: 12, weight: w.page == name ? .semibold : .regular))
                        Spacer()
                        if name == "Strings", let a = w.analysis { Text(a.strings.count.formatted()).font(.system(size: 9, design: .monospaced)).foregroundStyle(Color.atlasMuted) }
                    }.foregroundStyle(w.page == name ? Color.atlasAccent : Color.secondary).padding(.horizontal, 12).frame(height: 35).background(w.page == name ? Color.atlasAccent.opacity(0.09) : .clear, in: RoundedRectangle(cornerRadius: 6))
                }.buttonStyle(.plain).padding(.horizontal, 10).help(Help.text(name))
            }
            Spacer()
            if let a = w.analysis {
                VStack(alignment: .leading, spacing: 9) {
                    Text("LOADED BINARY").font(.system(size: 8, weight: .bold)).tracking(1.5).foregroundStyle(Color.atlasMuted)
                    Text(a.name).font(.system(size: 12, weight: .medium)).lineLimit(2)
                    HStack { StatusPill(text: a.format, color: .atlasAccent); Text(a.arch).font(.system(size: 10, design: .monospaced)).foregroundStyle(.secondary) }
                    Text("ENTRY  \(a.entry)").help(Help.text("Entry point")).font(.system(size: 9, design: .monospaced)).foregroundStyle(Color.atlasMuted)
                }.padding(15).frame(maxWidth: .infinity, alignment: .leading).background(Color.white.opacity(0.025), in: RoundedRectangle(cornerRadius: 8)).padding(12)
            }
            Text("Original decompiler · LLVM · LLDB").font(.system(size: 9)).foregroundStyle(Color.atlasMuted).padding(.horizontal, 24).padding(.bottom, 17)
        }.frame(maxHeight: .infinity).background(Color.atlasPanel.opacity(0.6))
    }
}
struct StatusPill: View {
    var text: String; var color: Color
    var body: some View { Text(text).font(.system(size: 9, weight: .semibold, design: .monospaced)).padding(.horizontal, 7).padding(.vertical, 4).foregroundStyle(color).background(color.opacity(0.1), in: RoundedRectangle(cornerRadius: 4)) }
}
struct WelcomeView: View {
    @EnvironmentObject var w: Workspace
    var body: some View {
        VStack(alignment: .leading, spacing: 23) {
            HStack(spacing: 10) { Image(systemName: "asterisk.circle").font(.system(size: 40, weight: .ultraLight)); Text("UNDERSTAND WHAT'S INSIDE").font(.system(size: 10, weight: .semibold)).tracking(2) }.foregroundStyle(Color.atlasAccent)
            Text("From bytes to behavior.").font(.system(size: 38, weight: .semibold))
            Text("Inspect executable code, map its structure, and follow it through a real debugger. A native workspace for the details that matter.").font(.system(size: 15)).foregroundStyle(.secondary).lineSpacing(5).frame(maxWidth: 570, alignment: .leading)
            HStack(spacing: 10) { StatusPill(text: "MACH-O / UNIVERSAL", color: .atlasAccent); StatusPill(text: "WINDOWS PE / COFF", color: .atlasGold); StatusPill(text: "LINUX ELF", color: .blue) }
            HStack(spacing: 12) { Button("Open a binary…") { w.openPanel() }.help(Help.text("Open a binary…")).buttonStyle(.borderedProminent); Button("Explore training binary") { w.openSample() }.help(Help.text("Explore training binary")).buttonStyle(.bordered) }.controlSize(.large).padding(.top, 8)
            if !w.recent.isEmpty {
                Divider().padding(.vertical, 12)
                Text("RECENT FILES").font(.system(size: 9, weight: .bold)).tracking(2).foregroundStyle(Color.atlasMuted)
                ForEach(w.recent.prefix(4), id: \.self) { path in
                    Button { w.open(URL(fileURLWithPath: path)) } label: { HStack { Image(systemName: "doc"); Text(URL(fileURLWithPath: path).lastPathComponent); Spacer(); Image(systemName: "arrow.up.right") }.font(.system(size: 12)).foregroundStyle(.secondary) }.buttonStyle(.plain).help("Open recent binary: " + path)
                }
            }
            Text("Drop a file anywhere to inspect it. Static analysis never launches the binary.").font(.system(size: 11)).foregroundStyle(Color.atlasMuted).padding(.top, 16)
        }.padding(55).frame(maxWidth: 800, maxHeight: .infinity, alignment: .center)
    }
}
struct EmptyPanel: View {
    var icon = "square.dashed"; var title: String; var detail: String
    var body: some View { VStack(spacing: 15) { Image(systemName: icon).font(.system(size: 32, weight: .light)).foregroundStyle(Color.atlasMuted); Text(title).font(.headline); Text(detail).font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth: 430) }.padding(32).frame(maxWidth: .infinity, maxHeight: .infinity) }
}
struct MonoText: View {
    var text: String
    var body: some View { ScrollView([.horizontal, .vertical]) { Text(text.isEmpty ? "—" : text).font(.system(size: 11, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .topLeading).padding(16) }.background(Color.black.opacity(0.1)) }
}
