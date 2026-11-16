import Foundation
import AppKit
import SwiftUI

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
