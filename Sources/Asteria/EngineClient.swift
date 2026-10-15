import Foundation

struct EngineError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

final class EngineClient: @unchecked Sendable {
    static func root() throws -> URL {
        let candidates = [ProcessInfo.processInfo.environment["ASTERIA_ROOT"].map { URL(fileURLWithPath: $0) }, Bundle.main.resourceURL, URL(fileURLWithPath: FileManager.default.currentDirectoryPath)].compactMap { $0 }
        for root in candidates where FileManager.default.fileExists(atPath: root.appendingPathComponent("Engine/worker.py").path) { return root }
        throw EngineError(message: "Analysis engine is missing. Rebuild with scripts/build.sh.")
    }
    static func process(debug: Bool) throws -> Process {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/xcrun")
        p.arguments = ["python3", "-B", try root().appendingPathComponent("Engine/worker.py").path] + (debug ? ["--debug"] : [])
        var env = ProcessInfo.processInfo.environment
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["PYTHONUNBUFFERED"] = "1"
        p.environment = env
        return p
    }
    private struct Envelope<T: Decodable>: Decodable {
        var ok: Bool
        var result: T?
        var error: String?
    }
    static func decode<T: Decodable>(_ data: Data, as type: T.Type) throws -> T {
        // decode straight into models; an NSDictionary -> JSON -> model round trip copies large disassembly responses several times
        let envelope = try JSONDecoder().decode(Envelope<T>.self, from: data)
        guard envelope.ok else { throw EngineError(message: envelope.error ?? "Engine request failed") }
        guard let result = envelope.result else { throw EngineError(message: "Empty engine response") }
        return result
    }
    private static let worker = StaticWorker()
    static func request<T: Decodable>(_ query: [String: Any], as type: T.Type) async throws -> T {
        try await worker.request(query, as: type)
    }
    static func shutdown() { worker.shutdown() }
}

/// Cancelling ends only this transaction, never a later request on the same worker; cancelled pending work is skipped before it starts.
private final class StaticRequest: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    private var process: Process?
    func check() throws {
        lock.lock(); defer { lock.unlock() }
        if cancelled { throw CancellationError() }
    }
    func activate(_ p: Process) throws {
        lock.lock(); defer { lock.unlock() }
        if cancelled { throw CancellationError() }
        process = p
    }
    func finish() { lock.lock(); process = nil; lock.unlock() }
    func cancel() {
        lock.lock(); cancelled = true
        if let process, process.isRunning { process.terminate() }
        process = nil; lock.unlock()
    }
}

private final class StaticWorker: @unchecked Sendable {
    private let queue = DispatchQueue(label: "app.asteria.static", qos: .userInitiated)
    private var process: Process?
    private var input: FileHandle?
    private var output: FileHandle?
    private var errors: Pipe?
    private var buffer = Data()
    private var requestID = 0
    func request<T: Decodable>(_ query: [String: Any], as type: T.Type) async throws -> T {
        let request = StaticRequest()
        // Encoding/decoding and pipe reads all run off the main actor.
        return try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { continuation in
                queue.async {
                    var responseComplete = false
                    var transactionStarted = false
                    do {
                        try request.check()
                        try self.start()
                        guard let p = self.process, let input = self.input, let output = self.output else { throw EngineError(message: "Static analysis worker is unavailable") }
                        try request.activate(p)
                        transactionStarted = true
                        defer { request.finish() }
                        self.requestID += 1
                        var message = query; message["id"] = self.requestID
                        let payload = try JSONSerialization.data(withJSONObject: message) + Data([10])
                        let timeout = DispatchWorkItem { if p.isRunning { p.terminate() } }
                        DispatchQueue.global().asyncAfter(deadline: .now() + 110, execute: timeout)
                        defer { timeout.cancel() }
                        try input.write(contentsOf: payload)
                        // Resume searching at the last scanned byte, so receiving
                        // a 24 MB analysis response is linear in its size.
                        var searched = self.buffer.startIndex
                        var end: Data.Index?
                        while end == nil {
                            end = self.buffer[searched...].firstIndex(of: 10)
                            if end != nil { break }
                            searched = self.buffer.endIndex
                            let chunk = output.availableData
                            guard !chunk.isEmpty else { throw EngineError(message: "Static analysis worker stopped. Retry the operation.") }
                            self.buffer.append(chunk)
                            if self.buffer.count > 128 * 1024 * 1024 { throw EngineError(message: "Analysis response exceeds 128 MiB") }
                        }
                        let data = Data(self.buffer[..<end!]); self.buffer.removeSubrange(...end!)
                        responseComplete = true
                        request.finish()
                        try request.check()
                        // Errors returned by the engine leave its valid cache alive.
                        let result = try EngineClient.decode(data, as: T.self)
                        try request.check()
                        continuation.resume(returning: result)
                    } catch {
                        // An interrupted pipe cannot be reused; a domain error in
                        // a complete response can. The next transaction reconnects.
                        if (transactionStarted && !responseComplete) || self.process?.isRunning != true || !self.buffer.isEmpty {
                            self.stop()
                        }
                        do { try request.check(); continuation.resume(throwing: error) }
                        catch { continuation.resume(throwing: CancellationError()) }
                    }
                }
            }
        }, onCancel: { request.cancel() })
    }
    private func start() throws {
        if process?.isRunning == true { return }
        stop()
        let p = try EngineClient.process(debug: false)
        p.arguments?.append("--static-session")
        let input = Pipe(), output = Pipe(), errors = Pipe()
        p.standardInput = input; p.standardOutput = output; p.standardError = errors
        errors.fileHandleForReading.readabilityHandler = { handle in _ = handle.availableData }
        try p.run()
        process = p; self.input = input.fileHandleForWriting; self.output = output.fileHandleForReading; self.errors = errors
    }
    private func stop() {
        if process?.isRunning == true { process?.terminate() }
        errors?.fileHandleForReading.readabilityHandler = nil
        try? input?.close(); try? output?.close()
        process = nil; input = nil; output = nil; errors = nil; buffer = Data()
    }
    func shutdown() { queue.async { self.stop() } }
}

final class DebugClient: @unchecked Sendable {
    private let queue = DispatchQueue(label: "app.asteria.debugger")
    private var process: Process?
    private var input: FileHandle?
    private var output: FileHandle?
    private var errors: Pipe?
    private var buffer = Data()
    func request(_ query: [String: Any]) async throws -> DebugSnapshot {
        let payload = try JSONSerialization.data(withJSONObject: query) + Data([10])
        let response: Data = try await withCheckedThrowingContinuation { continuation in
            queue.async {
                do {
                    if self.process?.isRunning != true {
                        let p = try EngineClient.process(debug: true)
                        let input = Pipe(), output = Pipe(), errors = Pipe()
                        p.standardInput = input; p.standardOutput = output; p.standardError = errors
                        errors.fileHandleForReading.readabilityHandler = { h in _ = h.availableData }
                        try p.run()
                        self.process = p; self.input = input.fileHandleForWriting; self.output = output.fileHandleForReading; self.errors = errors; self.buffer = Data()
                    }
                    guard let input = self.input, let output = self.output else { throw EngineError(message: "Debugger unavailable") }
                    let p = self.process
                    let timeout = DispatchWorkItem { if p?.isRunning == true { p?.terminate() } }
                    DispatchQueue.global().asyncAfter(deadline: .now() + 65, execute: timeout)
                    defer { timeout.cancel() }
                    try input.write(contentsOf: payload)
                    while self.buffer.firstIndex(of: 10) == nil {
                        let chunk = output.availableData
                        guard !chunk.isEmpty else { throw EngineError(message: "LLDB worker stopped. Prepare a new target to reconnect.") }
                        self.buffer.append(chunk)
                        if self.buffer.count > 32 * 1024 * 1024 { throw EngineError(message: "Debugger response exceeds limit") }
                    }
                    let end = self.buffer.firstIndex(of: 10)!
                    let line = Data(self.buffer[..<end]); self.buffer.removeSubrange(...end)
                    continuation.resume(returning: line)
                } catch {
                    self.process?.terminate(); self.process = nil
                    continuation.resume(throwing: error)
                }
            }
        }
        return try EngineClient.decode(response, as: DebugSnapshot.self)
    }
    func shutdown() {
        let finished = DispatchSemaphore(value: 0)
        queue.async {
            defer { finished.signal() }
            if self.process?.isRunning == true {
                try? self.input?.write(contentsOf: Data("{\"action\":\"shutdown\"}\n".utf8))
                try? self.input?.close()
                self.process?.waitUntilExit()
            }
        }
        if finished.wait(timeout: .now() + 2) == .timedOut { process?.terminate() }
    }
}
