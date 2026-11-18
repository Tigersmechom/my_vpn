import Foundation
import AppKit
import SwiftUI
import Darwin

struct AvailabilityResult: Decodable {
    let id: String
    let grade: String
    let code: String
    let rttMs: Int
    let averageMs: Int
    let jitterMs: Int
    let samples: Int
    let successes: Int
    let checkedAt: Double

    var color: Color { grade == "green" ? .green : grade == "red" ? .red : .yellow }
    var detail: String {
        if code == "ok" {
            return "\(rttMs) мс · успешно \(successes)/\(samples) · разброс \(jitterMs) мс"
        }
        let reason: String
        switch code {
        case "timeout": reason = "Нет ответа за время проверки"
        case "certificate": reason = "Не прошла проверка сертификата"
        case "auth": reason = "Сервер отклонил авторизацию"
        case "requires_probe_key": reason = "Нет отдельного ключа проверки — обновите конфигурацию"
        case "http_status": reason = "VPN ответил, контрольный сайт недоступен"
        case "cancelled": reason = "Проверка приостановлена"
        default: reason = "Не удалось открыть сайт через VPN"
        }
        return "\(reason) · успешно \(successes)/\(samples)"
    }
    var label: String { code == "ok" ? (grade == "green" ? "Хорошее соединение" : "Соединение с задержкой") : (grade == "red" ? "Соединение недоступно" : "Требует проверки") }
}

/// Unprivileged subprocess: private configuration travels over pipes, never command arguments.
final class AvailabilityProcess: @unchecked Sendable {
    private let lock = NSLock()
    private var process: Process?
    private var input: FileHandle?
    private var output: FileHandle?
    private var closed = false

    func stop() { reset(close: true) }

    private func reset(close: Bool = false) {
        lock.lock()
        if close { closed = true }
        let child = process
        let writer = input
        process = nil; input = nil; output = nil
        lock.unlock()
        try? writer?.close()
        if child?.isRunning == true { child?.terminate() }
    }

    func check(_ data: Data) async throws -> [AvailabilityResult] {
        try await withTaskCancellationHandler(operation: {
            try await Task.detached(priority: .utility) {
                do { return try self.exchange(data) }
                catch { self.reset(); throw error }
            }.value
        }, onCancel: { self.stop() })
    }

    private func exchange(_ data: Data) throws -> [AvailabilityResult] {
        lock.lock()
        if closed { lock.unlock(); throw CancellationError() }
        if process == nil {
            guard let executable = Bundle.main.url(forResource: "health-core", withExtension: nil) else {
                lock.unlock(); throw VPNError("Не найден компонент проверки")
            }
            let child = Process(), stdin = Pipe(), stdout = Pipe()
            child.executableURL = executable
            child.standardInput = stdin; child.standardOutput = stdout; child.standardError = FileHandle.nullDevice
            child.environment = ProcessInfo.processInfo.environment.merging(["GOMAXPROCS": "2"]) { _, new in new }
            do { try child.run() } catch { lock.unlock(); throw error }
            process = child; input = stdin.fileHandleForWriting; output = stdout.fileHandleForReading
        }
        let writer = input!, reader = output!
        lock.unlock()
        try writer.write(contentsOf: data + Data([10]))
        var reply = Data()
        while reply.count <= 1_048_576 {
            let chunk = reader.availableData
            if chunk.isEmpty { throw VPNError("Проверка остановлена") }
            reply.append(chunk)
            if reply.last == 10 { break }
        }
        struct Reply: Decodable { let results: [AvailabilityResult]?; let error: String? }
        let decoded = try JSONDecoder().decode(Reply.self, from: reply)
        guard decoded.error == nil, let results = decoded.results else { throw VPNError("Не удалось проверить конфигурацию") }
        return results
    }
    deinit { stop() }
}

/// Check catalog TCP modes through loopback SOCKS, without the privileged helper or TUN.
final class XrayAvailabilityProcess: @unchecked Sendable {
    private let lock = NSLock()
    private var stopped = false
    private var children: [Process] = []
    private var history: [String: [Int?]] = [:]
    private var fingerprints: [String: Data] = [:]
    private let executable: URL?
    private let requestExecutable: URL

    init(executable: URL? = Bundle.main.url(forResource: "xray", withExtension: nil),
         requestExecutable: URL = URL(fileURLWithPath: "/usr/bin/curl")) {
        self.executable = executable
        self.requestExecutable = requestExecutable
    }

    func stop() {
        lock.lock()
        stopped = true
        let running = children
        lock.unlock()
        for child in running where child.isRunning { child.terminate() }
    }

    private func launch(_ child: Process) throws {
        lock.lock()
        defer { lock.unlock() }
        guard !stopped else { throw CancellationError() }
        try child.run()
        children.append(child)
    }

    private func finish(_ child: Process) {
        if child.isRunning { child.terminate() }
        child.waitUntilExit()
        lock.lock()
        children.removeAll { $0 === child }
        lock.unlock()
    }

    func check(_ connections: [VPNConnection]) async throws -> [AvailabilityResult] {
        try await withTaskCancellationHandler(operation: {
            try await Task.detached(priority: .utility) {
                try connections.map { try self.probe($0) }
            }.value
        }, onCancel: { self.stop() })
    }

    private func port() throws -> Int {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw VPNError("Не удалось открыть проверку") }
        defer { Darwin.close(fd) }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        var size = socklen_t(MemoryLayout<sockaddr_in>.size)
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, size) }
        }
        guard bound == 0 else { throw VPNError("Не удалось открыть проверку") }
        let named = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &size) }
        }
        guard named == 0 else { throw VPNError("Не удалось открыть проверку") }
        return Int(UInt16(bigEndian: address.sin_port))
    }

    private func probe(_ connection: VPNConnection) throws -> AvailabilityResult {
        guard let outbound = connection.outbound, let executable else {
            throw VPNError("Не найден компонент проверки TCP")
        }
        let fingerprint = try JSONSerialization.data(withJSONObject: outbound, options: [.sortedKeys])
        if fingerprints[connection.id] != fingerprint { history[connection.id] = []; fingerprints[connection.id] = fingerprint }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("myvpn-tcp-probe-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        let port = try port()
        let config: [String: Any] = ["log": ["loglevel": "none"],
            "inbounds": [["listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": ["auth": "noauth", "udp": false]]],
            "outbounds": [outbound]]
        let file = directory.appendingPathComponent("config.json")
        try JSONSerialization.data(withJSONObject: config).write(to: file)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        let core = Process()
        core.executableURL = executable
        core.arguments = ["run", "-c", file.path]
        core.standardOutput = FileHandle.nullDevice; core.standardError = FileHandle.nullDevice
        core.environment = ProcessInfo.processInfo.environment.merging(["GOMAXPROCS": "2"]) { _, new in new }
        try launch(core)
        defer { finish(core) }
        Thread.sleep(forTimeInterval: 0.15)
        let request = Process(), output = Pipe()
        request.executableURL = requestExecutable
        request.arguments = ["--silent", "--head", "--max-time", "7", "--socks5-hostname", "127.0.0.1:\(port)",
                             "--output", "/dev/null", "--write-out", "%{http_code} %{time_total}", "https://www.google.com/generate_204"]
        request.standardOutput = output; request.standardError = FileHandle.nullDevice
        try launch(request)
        defer { finish(request) }
        request.waitUntilExit()
        lock.lock(); let cancelled = stopped; lock.unlock()
        guard !cancelled else { throw CancellationError() }
        let response = String(decoding: output.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self).split(separator: " ")
        let success = request.terminationStatus == 0 && response.first == "204"
        let ms = Int((response.count == 2 ? Double(response[1]) ?? 0 : 0) * 1000)
        let samples = Array(((history[connection.id] ?? []) + [success ? ms : nil]).suffix(5))
        history[connection.id] = samples
        let good = samples.compactMap { $0 }
        let failedTwice = samples.count >= 2 && samples.suffix(2).allSatisfy { $0 == nil }
        let grade = failedTwice ? "red" : (success && ms < 250 && good.count == samples.count ? "green" : "yellow")
        return AvailabilityResult(id: connection.id, grade: grade,
            code: success ? "ok" : (request.terminationStatus == 28 ? "timeout" : "unreachable"),
            rttMs: ms, averageMs: good.isEmpty ? 0 : good.reduce(0, +) / good.count,
            jitterMs: (good.max() ?? 0) - (good.min() ?? 0), samples: samples.count, successes: good.count,
            checkedAt: Date().timeIntervalSince1970 * 1000)
    }
    deinit { stop() }
}

/// Track the actual main window, including minimization and sheets; menu-bar presence is insufficient.
struct ForegroundWindow: NSViewRepresentable {
    let changed: (Bool) -> Void
    func makeNSView(context: Context) -> WatchView { WatchView(changed: changed) }
    func updateNSView(_ nsView: WatchView, context: Context) { nsView.changed = changed }
    final class WatchView: NSView {
        var changed: (Bool) -> Void
        private var observers: [NSObjectProtocol] = []
        init(changed: @escaping (Bool) -> Void) { self.changed = changed; super.init(frame: .zero) }
        required init?(coder: NSCoder) { fatalError() }
        override func viewDidMoveToWindow() {
            observers.forEach(NotificationCenter.default.removeObserver); observers = []
            let names: [Notification.Name] = [NSApplication.didBecomeActiveNotification, NSApplication.didResignActiveNotification,
                NSWindow.didBecomeKeyNotification, NSWindow.didResignKeyNotification, NSWindow.didMiniaturizeNotification,
                NSWindow.didDeminiaturizeNotification, NSWindow.didChangeOcclusionStateNotification, NSWindow.willCloseNotification]
            for name in names {
                observers.append(NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main) { [weak self] notification in
                    guard let self else { return }
                    if notification.name == NSWindow.willCloseNotification, let closed = notification.object as? NSWindow, closed === self.window {
                        self.changed(false)
                    } else { self.report() }
                })
            }
            DispatchQueue.main.async { [weak self] in self?.report() }
        }
        private func report() {
            guard let window else { changed(false); return }
            changed(NSApp.isActive && window.isVisible && !window.isMiniaturized && window.occlusionState.contains(.visible))
        }
        deinit { observers.forEach(NotificationCenter.default.removeObserver) }
    }
}
