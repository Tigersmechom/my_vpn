import AppKit
import Foundation

/// Обёртка над привилегированным helper'ом: установка (один раз, с паролем администратора)
/// и вызовы через `sudo -n` по правилу из /etc/sudoers.d/myvpn.
enum Helper {
    static let installedPath = "/Library/PrivilegedHelperTools/myvpn/myvpn-helper"

    static var resources: URL { Bundle.main.resourceURL! }

    /// Версия helper'а, вшитого в это приложение (строка VERSION=N в скрипте).
    static var bundledVersion: String {
        let text = (try? String(contentsOf: resources.appendingPathComponent("myvpn-helper"))) ?? ""
        return text.split(separator: "\n")
            .first { $0.hasPrefix("VERSION=") }
            .map { String($0.dropFirst("VERSION=".count)) } ?? "?"
    }

    static func installedVersion() -> String? {
        guard FileManager.default.isExecutableFile(atPath: installedPath) else { return nil }
        return try? run(["version"]).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    static var isReady: Bool { installedVersion() == bundledVersion }

    @discardableResult
    static func run(_ args: [String]) throws -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
        p.arguments = ["-n", installedPath] + args
        let out = Pipe(), err = Pipe()
        p.standardOutput = out
        p.standardError = err
        try p.run()
        p.waitUntilExit()
        let stdout = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        let stderr = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        guard p.terminationStatus == 0 else {
            let msg = stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            throw VPNError(msg.isEmpty ? "helper завершился с кодом \(p.terminationStatus)" : msg)
        }
        return stdout
    }

    static func install() throws {
        let script = resources.appendingPathComponent("install-helper.sh").path
        try runAsAdmin("/bin/bash \(shellQuote(script)) install \(shellQuote(resources.path)) \(getuid())")
    }

    static func uninstall() throws {
        let script = resources.appendingPathComponent("install-helper.sh").path
        try runAsAdmin("/bin/bash \(shellQuote(script)) uninstall")
    }

    /// Стандартное системное окно с запросом пароля администратора.
    private static func runAsAdmin(_ command: String) throws {
        let escaped = command.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        let source = "do shell script \"\(escaped)\" with prompt \"My VPN устанавливает компонент для управления сетью\" with administrator privileges"
        var error: NSDictionary?
        guard let script = NSAppleScript(source: source) else { throw VPNError("AppleScript недоступен") }
        script.executeAndReturnError(&error)
        if let error {
            throw VPNError((error[NSAppleScript.errorMessage] as? String) ?? "Установка отменена")
        }
    }

    private static func shellQuote(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }
}
