import Foundation

struct Analysis: Codable {
    var path, name, format, arch, endian, entry, imageBase, sha256, md5: String
    var size, bits, selectedSlice: Int
    var entropy: Double
    var sections, regions: [BinarySection]
    var symbols, imports, exports: [BinarySymbol]
    var libraries, warnings: [String]
    var headers: [HeaderField]
    var slices: [BinarySlice]
    var members: [ArchiveMember]
    var strings: [BinaryString]
    var instructions: [Instruction]
    var functions: [BinaryFunction]
    var xrefs: [Reference]
    var entropyBins: [EntropyBin]
    var recognition: RecognitionSummary? = nil
}
struct HeaderField: Codable, Identifiable { var name, value: String; var id: String { name + value } }
struct BinarySection: Codable, Identifiable {
    var name, address: String; var offset, size, virtualSize: Int; var flags: String; var entropy: Double
    var id: String { name + address + String(offset) }
}
struct BinarySymbol: Codable, Identifiable {
    var name, address, kind, library: String; var size: Int
    var id: String { name + address + kind }
}
struct BinarySlice: Codable, Identifiable { var index: Int; var arch: String; var offset, size: Int; var id: Int { index } }
struct ArchiveMember: Codable, Identifiable { var name: String; var offset, size: Int; var id: Int { offset } }
struct BinaryString: Codable, Identifiable {
    var offset: Int; var address, encoding, value: String
    var id: String { String(offset) + encoding }
}
struct Instruction: Codable, Identifiable {
    var address: String; var offset: Int; var mnemonic, operands, function, section, kind, target, bytes: String
    var id: String { section + address }
}
struct BinaryFunction: Codable, Identifiable {
    var name, address: String; var count: Int; var end: String
    var originalName: String? = nil
    var nameSource: String? = nil
    var library: String? = nil
    var id: String { address + (originalName ?? name) }
}
struct Reference: Codable, Identifiable { var source, target, kind, function: String; var id: String { source + target } }
struct EntropyBin: Codable { var offset: Int; var value: Double }
struct HexResult: Codable { var text: String; var offset, total: Int }
struct SearchHit: Codable, Identifiable { var offset: Int; var bytes: String; var id: Int { offset } }
struct SearchResult: Codable { var hits: [SearchHit]; var truncated: Bool }
struct DiffRun: Codable, Identifiable { var offset, size: Int; var before, after: String; var id: Int { offset } }
struct DiffResult: Codable { var changed, leftSize, rightSize: Int; var runs: [DiffRun]; var truncated: Bool }
struct PatchResult: Codable { var path, sha256: String; var count: Int }
struct Annotation: Codable, Identifiable {
    var address, label, comment: String; var bookmark: Bool
    var id: String { address }
}
struct ProjectFile: Codable {
    var version = 1
    var path, sha256: String
    var slice: Int
    var annotations: [Annotation]
    var decompilerNames: [String: [String: String]]? = nil
    var functionNames: [String: [String: String]]? = nil
    var followCode: Bool? = nil
}
struct RecognitionSummary: Codable {
    var engine: String; var signatures: Int; var libraries, warnings: [String]
    var matches: [RecognitionMatch]; var ambiguities: [RecognitionAmbiguity]
}
struct RecognitionMatch: Codable, Identifiable {
    var address, name, library: String; var instructions, size: Int; var applied: Bool
    var id: String { address + name }
}
struct RecognitionAmbiguity: Codable, Identifiable { var address: String; var names: [String]; var id: String { address } }
struct SignatureEntry: Codable { var name, arch, endian: String; var bits, size: Int; var ops: [String] }
struct SignaturePack: Codable { var schema, library: String; var entries: [SignatureEntry]; var sourceHash: String? }
struct SignatureLearning: Codable { var pack: SignaturePack; var count: Int; var skipped: [String] }
struct SignatureInstallation: Codable { var path, library: String; var count: Int }
struct RenameTarget: Identifiable, Equatable {
    var functionAddress: String
    var variable: String? = nil
    var id: String { functionAddress + ":" + (variable ?? "function") }
}
struct RenameContext: Identifiable {
    var function: BinaryFunction
    var variables: [RecoveredVariable]
    var selected: String
    var instruction: String
    var id: String { function.address }
}

/// Rebuilt once per analysis so visible rows, tooltips and selection updates never scan the whole image.
struct AnalysisIndex {
    var functionsByName: [String: BinaryFunction] = [:]
    var functionsByAddress: [String: BinaryFunction] = [:]
    var instructionsByAddress: [String: Instruction] = [:]
    var instructionsByFunction: [String: [Instruction]] = [:]
    var referencesByAddress: [String: [Reference]] = [:]
    init(_ analysis: Analysis? = nil) {
        guard let a = analysis else { return }
        functionsByName.reserveCapacity(a.functions.count); functionsByAddress.reserveCapacity(a.functions.count)
        instructionsByAddress.reserveCapacity(a.instructions.count)
        for f in a.functions {
            if functionsByName[f.name] == nil { functionsByName[f.name] = f }
            if functionsByAddress[f.address] == nil { functionsByAddress[f.address] = f }
        }
        for i in a.instructions {
            if instructionsByAddress[i.address] == nil { instructionsByAddress[i.address] = i }
            instructionsByFunction[i.function, default: []].append(i)
        }
        for r in a.xrefs {
            referencesByAddress[r.source, default: []].append(r)
            if r.source != r.target { referencesByAddress[r.target, default: []].append(r) }
        }
    }
}

struct CodeNameIndex {
    var targets: [(String, RenameTarget)] = []
    var byName: [String: Int] = [:]
    init(functions: [BinaryFunction] = [], result: Decompilation? = nil) {
        if let result {
            targets = result.variables.map { ($0.displayName, RenameTarget(functionAddress: result.function.address, variable: $0.name)) }
        }
        for f in functions {
            let stripped = String(f.name.drop(while: { $0 == "_" }))
            let clean = stripped.replacingOccurrences(of: "[^A-Za-z0-9_]", with: "_", options: .regularExpression)
            let name = clean.first?.isNumber == true ? "fn_" + clean : clean
            targets.append((name, RenameTarget(functionAddress: f.address)))
        }
        for (index, entry) in targets.enumerated() where byName[entry.0] == nil { byName[entry.0] = index }
    }
}
struct DebugSnapshot: Codable {
    var state, description, triple, output, pc, assembly, result, targetPath, platform: String
    var pid: UInt64
    var breakpoints: [DebugBreakpoint]
    var threads: [DebugThread]
    var frames: [DebugFrame]
    var registers: [DebugRegister]
    var variables: [DebugVariable]
    var modules: [DebugModule]
    static let empty = DebugSnapshot(state: "idle", description: "Prepare a target to begin", triple: "", output: "", pc: "", assembly: "", result: "", targetPath: "", platform: "host", pid: 0, breakpoints: [], threads: [], frames: [], registers: [], variables: [], modules: [])
    var stopped: Bool { ["stopped", "crashed", "suspended"].contains(state) }
    var active: Bool { !["idle", "ready", "invalid", "exited", "detached", "unloaded"].contains(state) }
}
struct DebugBreakpoint: Codable, Identifiable { var id: Int; var enabled: Bool; var locations, hits: Int; var condition, description: String }
struct DebugThread: Codable, Identifiable { var id: UInt64; var index: Int; var name, reason: String; var selected: Bool }
struct DebugFrame: Codable, Identifiable { var id: Int; var address, name, location: String; var selected: Bool }
struct DebugRegister: Codable, Identifiable { var name, value, group: String; var id: String { group + name } }
struct DebugVariable: Codable, Identifiable { var name, value, type: String; var id: String { name + type } }
struct DebugModule: Codable, Identifiable { var name, address, uuid: String; var id: String { name + address } }

func addressValue(_ string: String) -> UInt64? {
    let s = string.trimmingCharacters(in: .whitespacesAndNewlines)
    return s.lowercased().hasPrefix("0x") ? UInt64(s.dropFirst(2), radix: 16) : UInt64(s, radix: 16)
}
func hex(_ value: Int) -> String { String(format: "0x%x", value) }
func humanSize(_ size: Int) -> String { ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file) }

struct Decompilation: Codable {
    var version, arch, abi, sha256, text: String
    var slice: Int
    var function: BinaryFunction
    var lines: [PseudocodeLine]
    var variables: [RecoveredVariable]
    var diagnostics: [String]
    var instructions: [Instruction]
    var blocks: [DecompilerBlock]
    var ir, optimizedIR: [LiftedOperation]
    var reverseMap: [String: [Int]]
    var coverage: DecompilerCoverage
}
struct PseudocodeLine: Codable, Identifiable {
    var id: Int
    var text, kind, explanation: String
    var addresses: [String]
    var spans: [InstructionSpan]
}
struct InstructionSpan: Codable, Identifiable {
    var address, bytes: String
    var offset, size: Int
    var id: String { address }
}
struct RecoveredVariable: Codable, Identifiable {
    var name, type, kind, storage, displayName: String
    var addresses: [String]
    var id: String { name }
}
struct DecompilerBlock: Codable, Identifiable {
    var address: String
    var successors, predecessors, liveIn, liveOut: [String]
    var id: String { address }
}
struct LiftedOperation: Codable {
    var block, kind, destination, expression, target, detail: String
    var arguments, addresses: [String]
}
struct DecompilerCoverage: Codable {
    var total, mapped, lifted, unsupported, blocks, loops, conditionals: Int
}
struct InstructionPatchPreview: Codable {
    var address, before, after, original, replacement, sha256, kind, warning: String
    var offset, size: Int
}
