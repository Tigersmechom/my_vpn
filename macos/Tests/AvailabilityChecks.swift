import Foundation
import Darwin

@main
struct AvailabilityChecks {
    static func main() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("myvpn-availability-tests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        func script(_ name: String, _ body: String) throws -> URL {
            let file = directory.appendingPathComponent(name)
            try ("#!/bin/sh\n" + body + "\n").write(to: file, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: file.path)
            return file
        }
        let core = try script("xray", "exec /bin/sleep 30")
        let request = try script("request", "printf '204 0.050'")
        let process = XrayAvailabilityProcess(executable: core, requestExecutable: request)
        defer { process.stop() }
        var outbound: [String: Any] = ["protocol": "vless", "settings": ["address": "example.com", "port": 443]]
        func connection() -> VPNConnection { VPNConnection(id: "custom-test", title: "Test", outbound: outbound) }
        let first = try await process.check([connection()])[0]
        precondition(first.grade == "green" && first.rttMs == 50 && first.samples == 1)
        _ = try script("request", "printf '000 0'; exit 28")
        let failed = try await process.check([connection()])[0]
        let failedAgain = try await process.check([connection()])[0]
        precondition(failed.grade == "yellow" && failedAgain.grade == "red" && failedAgain.code == "timeout")
        outbound["settings"] = ["address": "changed.example.com", "port": 443]
        let replaced = try await process.check([connection()])[0]
        precondition(replaced.grade == "yellow" && replaced.samples == 1)
        let pids = directory.appendingPathComponent("pids")
        _ = try script("request", "echo $$ >> '\(pids.path)'; exec /bin/sleep 30")
        let pending = Task { try await process.check([connection()]) }
        for _ in 0..<60 {
            if FileManager.default.fileExists(atPath: pids.path) { break }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        precondition(FileManager.default.fileExists(atPath: pids.path))
        let start = Date()
        pending.cancel()
        do { _ = try await pending.value; preconditionFailure("Cancelled check returned results") }
        catch is CancellationError { }
        precondition(Date().timeIntervalSince(start) < 3)
        let ids = try String(contentsOf: pids).split(separator: "\n").compactMap { Int32($0) }
        precondition(!ids.isEmpty && ids.allSatisfy { kill($0, 0) != 0 })
        print("TCP availability history, server replacement and foreground cancellation passed; no network requests or TUN")
    }
}
