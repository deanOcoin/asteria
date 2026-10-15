import AppKit
import SwiftUI

struct DebugWorkspace: View {
    @EnvironmentObject var w: Workspace
    var body: some View {
        VStack(spacing: 0) {
            DebugToolbar()
            Divider().opacity(0.35)
            Group {
                switch w.page {
                case "Session": DebugSessionView()
                case "Breakpoints": BreakpointsView()
                case "Threads & Stack": ThreadsView()
                case "Registers": RegistersView()
                case "Variables": VariablesView()
                case "Modules": ModulesView()
                case "Memory": DebugMemoryView()
                case "Console": DebugConsoleView()
                default: DebugSessionView()
                }
            }.frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}
struct DebugToolbar: View {
    @EnvironmentObject var w: Workspace
    var body: some View {
        HStack(spacing: 14) {
            Button { w.debugAction("continue") } label: { Label("Continue", systemImage: "play.fill") }.help("Resume the stopped process until a breakpoint, signal, exit or manual pause. F5.").disabled(!w.debug.stopped)
            Button { w.debugAction("pause") } label: { Image(systemName: "pause.fill") }.help("Pause execution").disabled(!w.debug.active || w.debug.stopped)
            Divider().frame(height: 18)
            Button { w.debugAction("instructionOver") } label: { Label("Over", systemImage: "arrow.turn.up.right") }.help("Step over one instruction · F6").disabled(!w.debug.stopped)
            Button { w.debugAction("instructionInto") } label: { Label("Into", systemImage: "arrow.down.to.line") }.help("Step into one instruction · F7").disabled(!w.debug.stopped)
            Button { w.debugAction("stepOut") } label: { Label("Out", systemImage: "arrow.up.to.line") }.help("Finish selected frame · F8").disabled(!w.debug.stopped)
            Menu("Source step") { Button("Step into source") { w.debugAction("stepInto") }.help(Help.text("Step into source")); Button("Step over source") { w.debugAction("stepOver") }.help(Help.text("Step over source")) }.help(Help.text("Source step")).frame(width: 110).disabled(!w.debug.stopped)
            Spacer()
            if w.debug.pid > 0 { Text("PID \(w.debug.pid)").help("Operating-system process identifier for the current debug target.").font(.system(size: 10, design: .monospaced)).foregroundStyle(Color.atlasMuted) }
            Button("Detach") { w.debugAction("detach") }.help(Help.text("Detach")).disabled(!w.debug.active)
            Button { w.debugAction("kill") } label: { Image(systemName: "stop.fill").foregroundStyle(Color.red.opacity(0.85)) }.help("Terminate debugged process").disabled(!w.debug.active)
        }.controlSize(.small).padding(.horizontal, 18).frame(height: 44).disabled(w.debugBusy)
    }
}
struct DebugSessionView: View {
    @EnvironmentObject var w: Workspace
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                HStack(alignment: .top, spacing: 16) {
                    VStack(alignment: .leading, spacing: 14) {
                        panelTitle("TARGET & LAUNCH", icon: "scope")
                        Text(w.analysis?.name ?? "Open a binary in Static analysis first").font(.system(size: 17, weight: .medium))
                        Picker("Platform", selection: $w.launchPlatform) { Text("Local macOS").tag("host"); Text("Remote Linux").tag("remote-linux"); Text("Remote Windows").tag("remote-windows"); Text("Remote gdb server").tag("remote-gdb-server") }.help(Help.text("Platform"))
                        HStack { Button("Prepare target") { if let a = w.analysis { w.debugAction("target", ["path": a.path, "platform": w.launchPlatform]) } }.help(Help.text("Prepare target")).disabled(w.analysis == nil || w.debug.active || w.debugBusy); Text(w.debug.triple).help("LLDB target triple: processor, vendor and operating system used for decoding and debugging.").font(.system(size: 9, design: .monospaced)).foregroundStyle(Color.atlasMuted).lineLimit(1) }
                        Divider().opacity(0.4)
                        TextField("Arguments (shell-style quoting)", text: $w.launchArguments).help(Help.text("Arguments (shell-style quoting)"))
                        TextField("Working directory (defaults to binary folder)", text: $w.launchDirectory).help(Help.text("Working directory (defaults to binary folder)"))
                        DisclosureGroup("Environment overrides") { TextEditor(text: $w.launchEnvironment).help(Help.text("Environment overrides")).font(.system(size: 11, design: .monospaced)).frame(height: 65); Text("One NAME=value entry per line").font(.caption).foregroundStyle(.secondary) }.help(Help.text("Environment overrides"))
                        Toggle("Stop at entry", isOn: $w.stopAtEntry).help(Help.text("Stop at entry")).font(.system(size: 11))
                        Button { w.debugAction("launch", ["arguments": w.launchArguments, "cwd": w.launchDirectory, "environment": w.launchEnvironment, "stopAtEntry": w.stopAtEntry]) } label: { Label("Launch locally", systemImage: "play.fill") }.help("Execute the prepared Mach-O target on this Mac with the configured arguments, directory, environment and entry stop.").buttonStyle(.borderedProminent).disabled(!w.debugStarted || w.debug.active || w.debugBusy || w.debugTargetPlatform != "host")
                        Text("Launch executes the prepared Mach-O binary on this Mac. Debugger access follows macOS permissions.").font(.system(size: 10)).foregroundStyle(.secondary)
                    }.padding(20).frame(maxWidth: .infinity, alignment: .topLeading).background(Color.atlasPanel, in: RoundedRectangle(cornerRadius: 9))
                    VStack(alignment: .leading, spacing: 15) {
                        panelTitle("ATTACH & REMOTE", icon: "cable.connector")
                        HStack { TextField("Process ID", text: $w.attachPID).help(Help.text("Process ID")).font(.system(size: 12, design: .monospaced)); Button("Attach PID") { guard let value = UInt64(w.attachPID), value > 0 else { w.error = "Enter a valid process ID"; return }; w.debugAction("attach", ["pid": value]) }.help(Help.text("Attach PID")).disabled(w.debug.active || w.debugBusy) }
                        Divider().opacity(0.4)
                        Text("GDB REMOTE STUB").font(.system(size: 8, weight: .bold)).tracking(1.4).foregroundStyle(Color.atlasMuted)
                        HStack { TextField("host:port", text: $w.remoteEndpoint).help(Help.text("host:port")).font(.system(size: 12, design: .monospaced)); Button("Connect") { w.debugAction("remote", ["endpoint": w.remoteEndpoint]) }.help(Help.text("Connect")).disabled(!w.debugStarted || w.debug.active || w.debugBusy) }
                        Text("Prepare the matching platform and local symbol file. Run the sample under lldb-server or a compatible stub on its target OS, then connect here.").font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                        Text("Linux example:\nlldb-server gdbserver 127.0.0.1:1234 ./sample").font(.system(size: 10, design: .monospaced)).textSelection(.enabled).padding(10).frame(maxWidth: .infinity, alignment: .leading).background(Color.black.opacity(0.2), in: RoundedRectangle(cornerRadius: 5))
                        Text("Use SSH port forwarding for a remote host. PE and ELF executables require a matching operating system; they do not launch locally.").font(.system(size: 10)).foregroundStyle(.secondary)
                        Divider().opacity(0.4)
                        Button("Load core dump…") { let panel = NSOpenPanel(); if panel.runModal() == .OK, let url = panel.url { w.debugAction("core", ["path": url.path]) } }.help(Help.text("Load core dump…")).disabled(w.debug.active || w.debugBusy)
                    }.padding(20).frame(maxWidth: .infinity, alignment: .topLeading).background(Color.atlasPanel, in: RoundedRectangle(cornerRadius: 9))
                }
                HStack { StatusPill(text: w.debug.state.uppercased(), color: w.debug.stopped ? .atlasGold : .atlasAccent); Text(w.debug.description).font(.system(size: 12)).foregroundStyle(.secondary); Spacer(); if !w.debug.pc.isEmpty { Text("RUNTIME PC  \(w.debug.pc)").help("Program counter at the current stop, including the runtime load slide.").font(.system(size: 11, design: .monospaced)).foregroundStyle(Color.atlasAccent) } }
                if !w.debugTargetPath.isEmpty { Text("PREPARED TARGET  \(w.debugTargetPath)").help("The LLDB target may differ from the file currently open in Static. Launch and breakpoints apply to this path.").font(.system(size: 10, design: .monospaced)).foregroundStyle(Color.atlasMuted).textSelection(.enabled) }
                HStack(alignment: .top, spacing: 16) {
                    VStack(alignment: .leading, spacing: 0) { panelTitle("LIVE DISASSEMBLY", icon: "text.alignleft").padding(14); MonoText(text: w.debug.assembly.isEmpty ? "Execution must be stopped to inspect instructions." : w.debug.assembly).frame(height: 270) }.frame(maxWidth: .infinity).background(Color.atlasPanel, in: RoundedRectangle(cornerRadius: 9))
                    VStack(alignment: .leading, spacing: 0) { panelTitle("PROCESS OUTPUT", icon: "terminal").padding(14); MonoText(text: w.console).frame(height: 270) }.frame(maxWidth: .infinity).background(Color.atlasPanel, in: RoundedRectangle(cornerRadius: 9))
                }
            }.padding(22)
        }
    }
    func panelTitle(_ title: String, icon: String) -> some View { HStack { Image(systemName: icon).foregroundStyle(Color.atlasAccent); Text(title).help(Help.text(title)).font(.system(size: 9, weight: .semibold)).tracking(1.4) } }
}
struct BreakpointsView: View {
    @EnvironmentObject var w: Workspace
    @State private var spec = "main"
    @State private var condition = ""
    var body: some View {
        VStack(spacing: 0) {
            HStack { TextField("Symbol or static address (0x…)", text: $spec).help(Help.text("Symbol or static address (0x…)")).font(.system(size: 12, design: .monospaced)); TextField("Optional condition", text: $condition).help(Help.text("Optional condition")); Button("Add breakpoint") { w.debugAction("breakpoint", ["spec": spec, "condition": condition]) }.help(Help.text("Add breakpoint")).disabled(!w.debugStarted || w.debugBusy) }.padding(16)
            HStack { Text("Address breakpoints use file virtual addresses and are relocated by LLDB. Right-click to enable, disable, or delete."); Spacer() }.font(.system(size: 10)).foregroundStyle(.secondary).padding(.horizontal, 18).padding(.bottom, 12)
            Table(w.debug.breakpoints) {
                TableColumn("ID") { Text(String($0.id)) .help("LLDB breakpoint identifier used by enable, disable and delete commands.") }.width(40)
                TableColumn("Enabled") { b in Button { w.debugAction("toggleBreakpoint", ["id": b.id]) } label: { Image(systemName: b.enabled ? "checkmark.circle.fill" : "circle").foregroundStyle(b.enabled ? Color.atlasAccent : Color.secondary) }.buttonStyle(.plain).help("Enable or disable this breakpoint while retaining its condition and location.") }.width(65)
                TableColumn("Locations") { Text(String($0.locations)) .help("Number of concrete breakpoint locations resolved by LLDB. Zero can mean the symbol or module is not loaded yet.") }.width(70)
                TableColumn("Hits") { Text(String($0.hits)) .help("Number of times this breakpoint has been hit during the debugging session.") }.width(55)
                TableColumn("Condition") { Text($0.condition).help("LLDB expression controlling whether this breakpoint should stop the target. Empty means unconditional.") }.width(min: 100, ideal: 170)
                TableColumn("Breakpoint") { b in Text(b.description).lineLimit(2).contextMenu { Button(b.enabled ? "Disable" : "Enable") { w.debugAction("toggleBreakpoint", ["id": b.id]) }; Button("Delete") { w.debugAction("deleteBreakpoint", ["id": b.id]) }.help(Help.text("Delete")) } }
            }.font(.system(size: 11, design: .monospaced))
            HStack { Text("Watchpoints via Console: watchpoint set variable atlas_counter").font(.system(size: 10, design: .monospaced)).foregroundStyle(Color.atlasMuted); Spacer(); Button("Open console") { w.page = "Console" }.help(Help.text("Open console")) }.padding(16)
        }
    }
}
struct ThreadsView: View {
    @EnvironmentObject var w: Workspace
    var threadSelection: Binding<UInt64?> {
        Binding(get: { w.debug.threads.first(where: \.selected)?.id }, set: { id in
            if let id, id != w.debug.threads.first(where: \.selected)?.id { w.debugAction("thread", ["id": id]) }
        })
    }
    var frameSelection: Binding<Int?> {
        Binding(get: { w.debug.frames.first(where: \.selected)?.id }, set: { id in
            if let id, id != w.debug.frames.first(where: \.selected)?.id { w.debugAction("frame", ["id": id]) }
        })
    }
    var body: some View {
        if !w.debug.stopped {
            EmptyPanel(icon: "pause.circle", title: "Pause to inspect threads", detail: "Thread and stack snapshots are available when the process is stopped.")
        } else {
            HSplitView {
                List(selection: threadSelection) {
                    ForEach(w.debug.threads) { thread in
                        VStack(alignment: .leading, spacing: 7) {
                            Text("Thread \(thread.index)  ·  \(thread.id)").font(.system(size: 12, weight: .semibold))
                            Text(thread.name).font(.caption)
                            Text(thread.reason).font(.system(size: 11)).foregroundStyle(Color.atlasGold)
                        }.padding(.vertical, 8).tag(thread.id).help("Select this stopped thread. Stop reason: " + thread.reason + ". Its stack frames will appear on the right.")
                    }
                }.frame(minWidth: 220, idealWidth: 280, maxWidth: 360).scrollContentBackground(.hidden)
                List(selection: frameSelection) {
                    ForEach(w.debug.frames) { frame in
                        HStack(alignment: .top, spacing: 16) {
                            Text("#\(frame.id)").foregroundStyle(frame.selected ? Color.atlasAccent : Color.atlasMuted).frame(width: 30)
                            VStack(alignment: .leading, spacing: 7) {
                                Text(frame.name).fontWeight(.medium)
                                Text(frame.address + "  " + frame.location).foregroundStyle(.secondary)
                            }
                            Spacer()
                            if frame.selected { Image(systemName: "arrow.left").foregroundStyle(Color.atlasAccent) }
                        }.font(.system(size: 11, design: .monospaced)).padding(.vertical, 8).tag(frame.id).help("Select this call frame to inspect its registers, variables and source location. Frame 0 is the innermost call.")
                    }
                }.scrollContentBackground(.hidden)
            }
        }
    }
}
struct RegistersView: View {
    @EnvironmentObject var w: Workspace
    var rows: [DebugRegister] { w.debug.registers.filter { w.filter.isEmpty || ($0.name + $0.group).localizedCaseInsensitiveContains(w.filter) } }
    var body: some View {
        VStack(spacing: 0) { FilterBar(text: $w.filter, placeholder: "Filter register names or groups", count: rows.count); if !w.debug.stopped { EmptyPanel(icon: "cpu", title: "Registers available at a stop", detail: "Launch or attach, then pause the process.") } else { Table(rows) { TableColumn("Register") { Text($0.name).help("Machine register name in the selected stopped frame.") }.width(140); TableColumn("Value") { r in Text(r.value).contextMenu { Button("Copy value") { w.copy(r.value) }.help(Help.text("Copy value")); Button("Inspect as memory") { w.memoryAddress = r.value; w.page = "Memory" }.help(Help.text("Inspect as memory")) } }; TableColumn("Register set") { Text($0.group).help("LLDB register bank or group, such as general purpose or floating point.") }.width(min: 180, ideal: 250) }.font(.system(size: 12, design: .monospaced)) }; HStack { Text("Edit a register in Console: register write <name> <value>").font(.system(size: 10, design: .monospaced)).foregroundStyle(Color.atlasMuted); Spacer() }.padding(16) }
    }
}
struct VariablesView: View {
    @EnvironmentObject var w: Workspace
    @State private var expression = ""
    @State private var result = ""
    var body: some View {
        VStack(spacing: 0) {
            HStack { TextField("Evaluate an expression in the selected frame", text: $expression).help(Help.text("Evaluate an expression in the selected frame")).font(.system(size: 12, design: .monospaced)).onSubmit { evaluate() }; Button("Evaluate") { evaluate() }.help(Help.text("Evaluate")).disabled(!w.debug.stopped || w.debugBusy || expression.isEmpty) }.padding(16)
            if !result.isEmpty { MonoText(text: result).frame(height: 90) }
            Table(w.debug.variables) { TableColumn("Variable") { Text($0.name).help("Local or argument name supplied by debug information for the selected frame.") }.width(min: 180, ideal: 250); TableColumn("Type") { Text($0.type).help("Type information supplied by LLDB debug metadata. Optimized-away values may be unavailable.") }.width(min: 160, ideal: 250); TableColumn("Value") { Text($0.value).help("Current value reported by LLDB for the selected stopped frame. It may change after stepping or selecting another frame.") } }.font(.system(size: 12, design: .monospaced))
            Text("Locals and arguments require debug information. Explicit expression evaluation can call code or change target state.").font(.system(size: 10)).foregroundStyle(Color.atlasMuted).padding(16).frame(maxWidth: .infinity, alignment: .leading)
        }.onChange(of: w.debug.result) { _, text in if !text.isEmpty { result = text } }
    }
    func evaluate() { w.debugAction("expression", ["expression": expression]) }
}
struct ModulesView: View {
    @EnvironmentObject var w: Workspace
    var rows: [DebugModule] { w.debug.modules.filter { w.filter.isEmpty || $0.name.localizedCaseInsensitiveContains(w.filter) } }
    var body: some View { VStack(spacing: 0) { FilterBar(text: $w.filter, placeholder: "Filter loaded modules", count: rows.count); Table(rows) { TableColumn("Module") { m in Text(m.name).contextMenu { Button("Copy path") { w.copy(m.name) }.help(Help.text("Copy path")) } }.width(min: 350, ideal: 600); TableColumn("Load address") { Text($0.address).help("Runtime load address after relocation or ASLR, suitable for process-memory inspection.") }.width(165); TableColumn("UUID") { Text($0.uuid).help("Module identifier used by LLDB to associate the loaded image with matching symbols.") }.width(min: 180, ideal: 300) }.font(.system(size: 11, design: .monospaced)) } }
}
struct DebugMemoryView: View {
    @EnvironmentObject var w: Workspace
    @State private var count = "256"
    @State private var text = ""
    var body: some View {
        VStack(spacing: 0) { HStack { TextField("Runtime address (0x…)", text: $w.memoryAddress).help(Help.text("Runtime address (0x…)")).font(.system(size: 12, design: .monospaced)).frame(width: 220); TextField("Bytes", text: $count).help(Help.text("Bytes")).frame(width: 80); Button("Read memory") { read() }.help(Help.text("Read memory")).disabled(!w.debug.stopped || w.debugBusy); Spacer(); Text("RUNTIME LOAD ADDRESSES").font(.system(size: 9, weight: .medium)).tracking(1).foregroundStyle(Color.atlasMuted) }.padding(16); MonoText(text: text); Text("Read up to 65,536 bytes. Console supports memory write, memory find, and memory region commands.").font(.system(size: 10)).foregroundStyle(Color.atlasMuted).padding(16).frame(maxWidth: .infinity, alignment: .leading) }.onAppear { if w.memoryAddress.isEmpty { w.memoryAddress = w.debug.pc } }.onChange(of: w.debug.result) { _, result in if !result.isEmpty { text = result } }
    }
    func read() { guard let size = Int(count), (1...65536).contains(size) else { w.error = "Enter a byte count from 1 to 65,536"; return }; w.debugAction("memory", ["address": w.memoryAddress, "count": size]) }
}
struct DebugConsoleView: View {
    @EnvironmentObject var w: Workspace
    @State private var command = ""
    @State private var stdin = ""
    var body: some View {
        VStack(spacing: 0) {
            HStack { Text("LLDB COMMAND CONSOLE").font(.system(size: 9, weight: .bold)).tracking(1.5).foregroundStyle(Color.atlasMuted); Spacer(); Menu("Recipes") { ForEach(["thread backtrace all", "register read", "image list -o -f", "memory region --all", "watchpoint set variable atlas_counter", "breakpoint list", "disassemble --frame", "help"], id: \.self) { value in Button(value) { command = value }.help("Fill the command input with: " + value + ". Press Run to execute it.") } }.help(Help.text("Recipes")); Button("Clear") { w.console = "" }.help(Help.text("Clear")); Button("Copy") { w.copy(w.console) }.help(Help.text("Copy")) }.padding(14)
            MonoText(text: w.console)
            HStack { Text("(lldb)").foregroundStyle(Color.atlasAccent); TextField("Enter an LLDB command", text: $command).help(Help.text("Enter an LLDB command")).textFieldStyle(.plain).onSubmit { send() }; Button("Run") { send() }.help(Help.text("Run")).disabled(command.isEmpty || w.debugBusy) }.font(.system(size: 12, design: .monospaced)).padding(16).background(Color.atlasPanel)
            HStack { Text("STDIN").font(.system(size: 9, weight: .bold)).foregroundStyle(Color.atlasMuted); TextField("Text to send to the running process", text: $stdin).help(Help.text("Text to send to the running process")); Button("Send line") { w.debugAction("stdin", ["text": stdin + "\n"]); stdin = "" }.help(Help.text("Send line")).disabled(!w.debug.active || w.debugBusy) }.padding(14)
        }
    }
    func send() { guard !command.isEmpty else { return }; w.console += "(lldb) \(command)\n"; w.debugAction("command", ["command": command]); command = "" }
}
