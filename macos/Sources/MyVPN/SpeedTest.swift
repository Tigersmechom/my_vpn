import Foundation

/// Тест скорости через speed.cloudflare.com: пинг (HTTP-запрос по уже открытому соединению),
/// скачивание и отдача по ~10 секунд. На Mac весь трафик приложения идёт через туннель.
enum SpeedTest {
    private static let base = "https://speed.cloudflare.com"
    private static let phase: TimeInterval = 10

    static func run(_ proto: VPNConnection, progress: @escaping @MainActor (String) -> Void) async throws -> SpeedResult {
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 15
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        let session = URLSession(configuration: config)
        defer { session.invalidateAndCancel() }

        await progress("Проверяю внешний IP…")
        let ip = (try? await session.data(from: URL(string: "https://api.ipify.org")!))
            .map { String(decoding: $0.0, as: UTF8.self) } ?? "?"

        await progress("Пинг…")
        var pings: [Int] = []
        for _ in 0..<6 {
            let t0 = Date()
            _ = try await session.data(from: URL(string: "\(base)/__down?bytes=0")!)
            pings.append(Int(Date().timeIntervalSince(t0) * 1000))
        }
        pings = Array(pings.dropFirst()).sorted() // первый — с TLS-рукопожатием
        let ping = pings[pings.count / 2]

        await progress("Скачивание…")
        let down = try await Meter.download(URL(string: "\(base)/__down?bytes=500000000")!, seconds: phase)

        await progress("Отдача…")
        var req = URLRequest(url: URL(string: "\(base)/__up")!)
        req.httpMethod = "POST"
        req.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        let up = try await Meter.upload(req, bytes: 100_000_000, seconds: phase)

        return SpeedResult(protocolRaw: proto.rawValue, time: Date().timeIntervalSince1970, pingMs: ping,
                           downMbps: down, upMbps: up, exitIp: ip.trimmingCharacters(in: .whitespacesAndNewlines), connectionTitle: proto.title)
    }
}

/// Считает байты через делегат и останавливает передачу по таймеру.
private final class Meter: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private var bytes: Int64 = 0
    private var start = Date()
    private var cont: CheckedContinuation<Double, Error>?
    private let lock = NSLock()

    static func download(_ url: URL, seconds: TimeInterval) async throws -> Double {
        try await Meter().run(seconds: seconds) { $0.dataTask(with: url) }
    }

    static func upload(_ req: URLRequest, bytes: Int, seconds: TimeInterval) async throws -> Double {
        let body = Data(count: bytes) // содержимое неважно: внутри TLS сжатия нет
        return try await Meter().run(seconds: seconds) { $0.uploadTask(with: req, from: body) }
    }

    private func run(seconds: TimeInterval, make: @escaping (URLSession) -> URLSessionTask) async throws -> Double {
        let session = URLSession(configuration: .ephemeral, delegate: self, delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        return try await withCheckedThrowingContinuation { c in
            cont = c
            start = Date()
            let task = make(session)
            task.resume()
            DispatchQueue.global().asyncAfter(deadline: .now() + seconds) { [weak self] in
                task.cancel()
                self?.finish(nil)
            }
        }
    }

    private func finish(_ error: Error?) {
        lock.lock()
        let c = cont
        cont = nil
        let elapsed = Date().timeIntervalSince(start)
        let total = bytes
        lock.unlock()
        guard let c else { return }
        if let error, total == 0 {
            c.resume(throwing: error)
        } else {
            c.resume(returning: elapsed > 0 ? Double(total) * 8 / elapsed / 1_000_000 : 0)
        }
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        lock.lock(); bytes += Int64(data.count); lock.unlock()
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didSendBodyData bytesSent: Int64,
                    totalBytesSent: Int64, totalBytesExpectedToSend: Int64) {
        lock.lock(); bytes = totalBytesSent; lock.unlock()
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        finish(error)
    }
}
