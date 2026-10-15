import SwiftUI

struct BasicBlock: Identifiable {
    var id: String
    var instructions: [Instruction]
    var successors: [(String, String)]
}
func makeBlocks(_ instructions: [Instruction]) -> [BasicBlock] {
    guard let first = instructions.first else { return [] }
    let addresses = Set(instructions.map(\.address))
    var leaders: Set<String> = [first.address]
    for (index, ins) in instructions.enumerated() {
        if ["jump", "branch"].contains(ins.kind), addresses.contains(ins.target) { leaders.insert(ins.target) }
        if ["jump", "branch", "return"].contains(ins.kind), index + 1 < instructions.count { leaders.insert(instructions[index + 1].address) }
    }
    var blocks: [BasicBlock] = []
    for ins in instructions {
        if leaders.contains(ins.address) { blocks.append(BasicBlock(id: ins.address, instructions: [], successors: [])) }
        if !blocks.isEmpty { blocks[blocks.count - 1].instructions.append(ins) }
    }
    let ids = Set(blocks.map(\.id))
    for i in blocks.indices {
        guard let last = blocks[i].instructions.last else { continue }
        if ["jump", "branch"].contains(last.kind), ids.contains(last.target) { blocks[i].successors.append((last.target, last.kind == "branch" ? "taken" : "jump")) }
        if !["jump", "return"].contains(last.kind), i + 1 < blocks.count { blocks[i].successors.append((blocks[i + 1].id, last.kind == "branch" ? "fallthrough" : "next")) }
    }
    return blocks
}
struct GraphView: View {
    @EnvironmentObject var w: Workspace
    let a: Analysis
    @State private var zoom = 1.0
    var source: [Instruction] { let name = w.selectedFunction.isEmpty ? a.functions.first?.name ?? "" : w.selectedFunction; return w.codeIndex.instructionsByFunction[name] ?? [] }
    var blocks: [BasicBlock] { Array(makeBlocks(Array(source.prefix(4000))).prefix(128)) }
    func rect(_ index: Int) -> CGRect { CGRect(x: 35 + (index % 3) * 340, y: 30 + (index / 3) * 220, width: 290, height: 170) }
    var body: some View {
        HSplitView {
            FunctionList(a: a)
            VStack(spacing: 0) {
                HStack { StatusPill(text: "\(blocks.count) BASIC BLOCKS", color: .atlasAccent); Text("Taken").help("Mint edges follow a conditional branch when its condition is true.").foregroundStyle(Color.atlasAccent); Text("Fallthrough").help("Gold edges follow the next instruction when a conditional branch is not taken.").foregroundStyle(Color.atlasGold); Spacer(); Slider(value: $zoom, in: 0.55...1.4).help("Zoom the control-flow graph from 55% to 140%.").frame(width: 110); Text("\(Int(zoom * 100))%").frame(width: 40) }.font(.system(size: 10)).padding(14)
                if blocks.isEmpty { EmptyPanel(icon: "point.3.connected.trianglepath.dotted", title: "No graph available", detail: "Select a function with decoded instructions.") }
                else {
                    ScrollView([.horizontal, .vertical]) {
                        Canvas { context, size in
                            let bs = blocks
                            for (i, block) in bs.enumerated() {
                                for (target, kind) in block.successors {
                                    guard let j = bs.firstIndex(where: { $0.id == target }) else { continue }
                                    let from = rect(i), to = rect(j)
                                    let start = CGPoint(x: from.maxX - 18, y: from.maxY)
                                    let end = CGPoint(x: to.minX + 18, y: to.minY)
                                    var path = Path(); path.move(to: start)
                                    if j > i { path.addCurve(to: end, control1: CGPoint(x: start.x + 25, y: start.y + 24), control2: CGPoint(x: end.x - 25, y: end.y - 24)) }
                                    else { let lane = max(from.maxX, to.maxX) + 22; path.addLine(to: CGPoint(x: lane, y: start.y + 12)); path.addLine(to: CGPoint(x: lane, y: to.minY - 14)); path.addLine(to: CGPoint(x: end.x, y: to.minY - 14)); path.addLine(to: end) }
                                    let color: Color = kind == "taken" ? .atlasAccent : kind == "fallthrough" ? .atlasGold : .blue.opacity(0.7)
                                    context.stroke(path, with: .color(color.opacity(0.7)), lineWidth: 1.3)
                                    var arrow = Path(); arrow.move(to: CGPoint(x: end.x - 4, y: end.y - 7)); arrow.addLine(to: end); arrow.addLine(to: CGPoint(x: end.x + 4, y: end.y - 7)); context.stroke(arrow, with: .color(color), lineWidth: 1.4)
                                }
                            }
                            for (i, block) in bs.enumerated() {
                                let r = rect(i); let shape = Path(roundedRect: r, cornerRadius: 7)
                                context.fill(shape, with: .color(.atlasPanel)); context.stroke(shape, with: .color(w.selectedAddress == block.id ? .atlasAccent : Color.white.opacity(0.14)), lineWidth: 1)
                                context.draw(Text(block.id + "  ·  \(block.instructions.count) instructions").font(.system(size: 10, weight: .semibold, design: .monospaced)).foregroundColor(.atlasAccent), at: CGPoint(x: r.minX + 12, y: r.minY + 16), anchor: .leading)
                                for (k, ins) in block.instructions.prefix(7).enumerated() {
                                    let label = ins.mnemonic.padding(toLength: 7, withPad: " ", startingAt: 0) + " " + ins.operands
                                    context.draw(Text(String(label.prefix(41))).font(.system(size: 9, design: .monospaced)).foregroundColor(ins.kind == "branch" ? .atlasGold : .white.opacity(0.75)), at: CGPoint(x: r.minX + 12, y: r.minY + 40 + CGFloat(k) * 16), anchor: .leading)
                                }
                                if block.instructions.count > 7 { context.draw(Text("… double-click to inspect full block").font(.system(size: 8)).foregroundColor(.atlasMuted), at: CGPoint(x: r.minX + 12, y: r.maxY - 10), anchor: .leading) }
                            }
                        }.frame(width: 1050, height: CGFloat((blocks.count + 2) / 3) * 220 + 40)
                        .help("Each block is a straight-line instruction sequence. Arrows show direct successors; double-click a block to inspect all its instructions. Indirect destinations are unresolved.")
                        .gesture(SpatialTapGesture(count: 2).onEnded { event in if let index = blocks.indices.first(where: { rect($0).contains(event.location) }) { w.navigate(blocks[index].id) } })
                        .scaleEffect(zoom, anchor: .topLeading).frame(width: 1050 * zoom, height: (CGFloat((blocks.count + 2) / 3) * 220 + 40) * zoom, alignment: .topLeading)
                    }
                }
                Text("Blocks are ordered by address; edges show direct flow. Indirect targets remain unresolved. View capped at 4,000 instructions / 128 blocks.").font(.system(size: 9)).foregroundStyle(Color.atlasMuted).padding(12).frame(maxWidth: .infinity, alignment: .leading)
            }.frame(minWidth: 560)
        }
    }
}
