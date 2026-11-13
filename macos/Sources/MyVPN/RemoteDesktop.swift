import AppKit
import Darwin
import Foundation
import SwiftUI
@preconcurrency import WebKit

private final class DesktopProbe: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false
    func set(_ flag: Bool) { lock.lock(); value = flag; lock.unlock() }
    var valid: Bool { lock.lock(); defer { lock.unlock() }; return value }
}

struct DesktopAccess: Decodable, Sendable {
    let host: String
    let user: String
    let hostKey: String
    let password: String
    static var directory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("MyVPN/Desktop", isDirectory: true)
    }

    static func load() throws -> DesktopAccess {
        let file = directory.appendingPathComponent("access.json")
        try checkPrivate(file)
        try checkPrivate(directory.appendingPathComponent("identity"))
        let data = try Data(contentsOf: file)
        guard data.count <= 16_384 else { throw VPNError("Некорректный файл доступа к рабочему столу") }
        let value = try JSONDecoder().decode(DesktopAccess.self, from: data)
        guard value.host.range(of: "^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$", options: .regularExpression) != nil,
              value.user.range(of: "^[a-z_][a-z0-9_-]{0,31}$", options: .regularExpression) != nil,
              value.hostKey.hasPrefix("ssh-ed25519 "), value.hostKey.split(separator: " ").count == 2,
              Data(base64Encoded: String(value.hostKey.split(separator: " ")[1])) != nil,
              !value.hostKey.contains("\n"), !value.hostKey.contains("\r"),
              value.password.utf8.count == 8 else { throw VPNError("Некорректные настройки рабочего стола") }
        return value
    }

    private static func checkPrivate(_ file: URL) throws {
        let attributes = try FileManager.default.attributesOfItem(atPath: file.path)
        guard attributes[.type] as? FileAttributeType == .typeRegular,
              (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == getuid(),
              ((attributes[.posixPermissions] as? NSNumber)?.intValue ?? 0) & 0o077 == 0 else {
            throw VPNError("У файла доступа к рабочему столу небезопасные права")
        }
    }
}

enum DesktopTunnel {
    static func open(_ access: DesktopAccess) throws -> (Process, URL) {
        let socketFD = socket(AF_INET, SOCK_STREAM, 0)
        guard socketFD >= 0 else { throw VPNError("Не удалось выделить локальный порт") }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bound = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(socketFD, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let named = withUnsafeMutablePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(socketFD, $0, &length) }
        }
        close(socketFD)
        guard bound == 0, named == 0 else { throw VPNError("Не удалось выделить локальный порт") }
        let port = UInt16(bigEndian: address.sin_port)
        let known = DesktopAccess.directory.appendingPathComponent("known_hosts")
        try "\(access.host),[\(access.host)]:22 \(access.hostKey)\n".write(to: known, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: known.path)
        let process = Process()
        let knownPath = known.path.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
        process.arguments = ["-F", "/dev/null", "-N", "-T", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
                             "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=\"\(knownPath)\"",
                             "-o", "ExitOnForwardFailure=yes", "-o", "ConnectTimeout=12",
                             "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=2",
                             "-i", DesktopAccess.directory.appendingPathComponent("identity").path,
                             "-L", "127.0.0.1:\(port):127.0.0.1:6080", "\(access.user)@\(access.host)"]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        let url = URL(string: "http://127.0.0.1:\(port)/myvpn.html")!
        // A bounded local HTTP read confirms the SSH forward and the expected viewer.
        for _ in 0..<30 {
            guard process.isRunning else { throw VPNError("SSH-доступ к рабочему столу отклонён. Проверьте ключ и доступность сервера") }
            let request = NSMutableURLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 0.6)
            let semaphore = DispatchSemaphore(value: 0)
            let probe = DesktopProbe()
            let session = URLSession(configuration: .ephemeral)
            let task = session.dataTask(with: request as URLRequest) { data, response, _ in
                probe.set((response as? HTTPURLResponse)?.statusCode == 200 && data.map { String(decoding: $0, as: UTF8.self).contains("myvpn-desktop-v1") } == true)
                semaphore.signal()
            }
            task.resume()
            _ = semaphore.wait(timeout: .now() + 1)
            task.cancel()
            session.invalidateAndCancel()
            if probe.valid { return (process, url) }
            Thread.sleep(forTimeInterval: 0.2)
        }
        process.terminate()
        throw VPNError("Рабочий стол не ответил. VPN-соединение можно продолжать использовать")
    }
}

@MainActor
final class DesktopSession: ObservableObject {
    @Published var url: URL?
    @Published var message = "Полный рабочий стол сервера США"
    @Published var connecting = false
    private(set) var password = ""
    private var process: Process?
    private var generation = UUID()

    func connect() {
        guard !connecting, url == nil else { return }
        connecting = true
        message = "Подключение к рабочему столу…"
        let attempt = UUID()
        generation = attempt
        Task {
            do {
                let access = try DesktopAccess.load()
                let result = try await Task.detached { try DesktopTunnel.open(access) }.value
                guard generation == attempt else { result.0.terminate(); return }
                process = result.0
                password = access.password
                process?.terminationHandler = { [weak self] _ in
                    Task { @MainActor in
                        guard let self, self.generation == attempt else { return }
                        self.url = nil
                        self.message = "SSH-соединение завершено. Нажмите «Подключить»"
                    }
                }
                url = result.1
                message = "Соединение защищено SSH · рабочий стол США"
            } catch {
                guard generation == attempt else { return }
                message = (error as? VPNError)?.message ?? "Не найден доступ к рабочему столу на этом Mac. Нужна персональная настройка ключа"
            }
            connecting = false
        }
    }

    func disconnect() {
        generation = UUID()
        process?.terminate()
        process = nil
        url = nil
        password = ""
        connecting = false
        message = "Просмотр отключён. Программы на сервере продолжают работать"
    }
}

struct RemoteDesktopView: View {
    @StateObject private var session = DesktopSession()
    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text(session.message).font(.caption)
                Spacer()
                if session.connecting { ProgressView().controlSize(.small) }
                Button(session.url == nil ? "Подключить" : "Отключить") {
                    session.url == nil ? session.connect() : session.disconnect()
                }.disabled(session.connecting)
            }.padding(10)
            Divider()
            if let url = session.url {
                DesktopWebView(url: url, password: session.password)
            } else {
                VStack(spacing: 12) {
                    Image(systemName: "display").font(.system(size: 52))
                    Text("Рабочий стол Ubuntu · США").font(.title2)
                    Text("Браузер, файловый менеджер и терминал работают на сервере.").foregroundStyle(.secondary)
                }.frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .frame(minWidth: 800, minHeight: 560)
        .onAppear { session.connect() }
        .onDisappear { session.disconnect() }
    }
}

struct DesktopWebView: NSViewRepresentable {
    let url: URL
    let password: String
    func makeCoordinator() -> Coordinator { Coordinator(url: url, password: password) }
    func makeNSView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .nonPersistent()
        configuration.userContentController.add(context.coordinator, name: "myvpnDesktopReady")
        let view = WKWebView(frame: .zero, configuration: configuration)
        view.navigationDelegate = context.coordinator
        view.load(URLRequest(url: url))
        return view
    }
    func updateNSView(_ view: WKWebView, context: Context) { }
    static func dismantleNSView(_ view: WKWebView, coordinator: Coordinator) {
        view.stopLoading()
        view.configuration.userContentController.removeScriptMessageHandler(forName: "myvpnDesktopReady")
    }
    final class Coordinator: NSObject, WKNavigationDelegate, WKScriptMessageHandler {
        let url: URL
        let password: String
        private var authenticated = false
        init(url: URL, password: String) { self.url = url; self.password = password }
        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            authenticate(webView)
        }
        func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
            guard message.name == "myvpnDesktopReady", message.body as? String == "ready", let view = message.webView else { return }
            authenticate(view)
        }
        private func authenticate(_ webView: WKWebView) {
            guard !authenticated, webView.url?.host == "127.0.0.1", webView.url?.port == url.port else { return }
            let encoded = try! JSONSerialization.data(withJSONObject: [password])
            let argument = String(decoding: encoded, as: UTF8.self)
            webView.evaluateJavaScript("typeof window.myvpnConnect === 'function' ? (window.myvpnConnect(...\(argument)), true) : false") { [weak self] result, _ in
                if result as? Bool == true { self?.authenticated = true }
            }
        }
        func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction,
                     decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
            guard let target = action.request.url, target.scheme == "http", target.host == "127.0.0.1", target.port == url.port else {
                decisionHandler(.cancel); return
            }
            decisionHandler(.allow)
        }
    }
}
