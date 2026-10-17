import Foundation
import CryptoKit

struct UpdateBootstrap {
    let client: String
    let url: URL
    let key: Data
    let minRevision: Int

    static func parse(_ data: Data) throws -> UpdateBootstrap {
        guard data.count <= 16_384,
              let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              object["format"] as? String == "myvpn-bootstrap-v1", object["client"] as? String == "mac",
              let rawURL = object["url"] as? String, let url = URL(string: rawURL),
              url.scheme == "https", url.host != nil, url.user == nil, url.password == nil, url.fragment == nil,
              let rawKey = object["key"] as? String, let key = Data(base64Encoded: rawKey), key.count == 32
        else { throw VPNError("Настройки обновления отсутствуют или некорректны") }
        return UpdateBootstrap(client: "mac", url: url, key: key, minRevision: try ProfileValidation.integer(object["minRevision"]))
    }

    static var bundled: UpdateBootstrap? {
        guard let url = Bundle.main.url(forResource: "update_bootstrap", withExtension: "json"),
              let data = try? Data(contentsOf: url) else { return nil }
        return try? parse(data)
    }
}

struct VerifiedUpdate {
    let profile: Profile
    let revision: Int
}

private final class HTTPSRedirects: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(request.url?.scheme == "https" ? request : nil)
    }
}

enum RemoteUpdates {
    static let maxBytes = 1_048_576

    /// GitHub/CDN может вернуть старую ревизию даже при отключённом локальном кэше.
    /// Меняем только добавленный параметр: исходные path и закодированный query сохраняются.
    static func requestURL(for url: URL, nonce: UUID = UUID()) throws -> URL {
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.scheme == "https", components.host != nil else {
            throw VPNError("Некорректный HTTPS-адрес обновления")
        }
        let suffix = "_myvpn_refresh=\(nonce.uuidString)"
        if let query = components.percentEncodedQuery, !query.isEmpty {
            components.percentEncodedQuery = query + "&" + suffix
        } else {
            components.percentEncodedQuery = suffix
        }
        guard let result = components.url else { throw VPNError("Некорректный адрес обновления") }
        return result
    }

    static func verify(_ data: Data, bootstrap: UpdateBootstrap, highestRevision: Int) throws -> VerifiedUpdate {
        do {
            guard data.count <= maxBytes,
                  let envelope = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  envelope["format"] as? String == "myvpn-update-v1",
                  envelope["client"] as? String == bootstrap.client,
                  let rawNonce = envelope["nonce"] as? String, let nonce = Data(base64Encoded: rawNonce), nonce.count == 12,
                  let rawCiphertext = envelope["ciphertext"] as? String,
                  let ciphertext = Data(base64Encoded: rawCiphertext), ciphertext.count >= 16
            else { throw VPNError("Некорректный формат обновления") }
            let revision = try ProfileValidation.integer(envelope["revision"])
            guard revision >= max(bootstrap.minRevision, highestRevision) else { throw VPNError("Устаревшее обновление отклонено") }
            let aad = Data("myvpn-update-v1\n\(bootstrap.client)\n\(revision)".utf8)
            let sealed = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce),
                                             ciphertext: ciphertext.dropLast(16), tag: ciphertext.suffix(16))
            let plaintext = try AES.GCM.open(sealed, using: SymmetricKey(data: bootstrap.key), authenticating: aad)
            guard plaintext.count <= maxBytes,
                  let payload = try JSONSerialization.jsonObject(with: plaintext) as? [String: Any],
                  try ProfileValidation.integer(payload["schema"]) == 1,
                  payload["client"] as? String == bootstrap.client,
                  try ProfileValidation.integer(payload["revision"]) == revision,
                  let profile = payload["profile"] as? [String: Any],
                  profile["client"] as? String == bootstrap.client
            else { throw VPNError("Некорректное содержимое обновления") }
            return VerifiedUpdate(profile: try ProfileValidation.profile(profile), revision: revision)
        } catch let error as VPNError {
            throw error
        } catch {
            throw VPNError("Проверка подлинности обновления не пройдена")
        }
    }

    /// `run -test` только разбирает конфигурацию: не создаёт TUN и не меняет сеть.
    static func validateExtraConfigs(_ profile: Profile, executable: URL) throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("myvpn-validation-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: directory) }
        for connection in profile.connections where connection.builtin == nil {
            let file = directory.appendingPathComponent("config.json")
            try Configs.xray(profile, connection).write(to: file, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
            let process = Process()
            process.executableURL = executable
            process.arguments = ["run", "-test", "-c", file.path]
            process.standardOutput = FileHandle.nullDevice
            process.standardError = FileHandle.nullDevice
            do { try process.run() } catch { throw VPNError("Не удалось проверить режим Xray; обновите приложение") }
            let deadline = Date().addingTimeInterval(5)
            while process.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.02) }
            if process.isRunning {
                kill(process.processIdentifier, SIGKILL)
                process.waitUntilExit()
                throw VPNError("Проверка режима Xray превысила время ожидания")
            }
            process.waitUntilExit()
            guard process.terminationStatus == 0 else {
                throw VPNError("Дополнительный режим несовместим с ядром Xray; проверьте профиль или обновите приложение")
            }
        }
    }

    static func fetch(bootstrap: UpdateBootstrap, highestRevision: Int) async throws -> VerifiedUpdate {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 15
        configuration.timeoutIntervalForResource = 30
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        let session = URLSession(configuration: configuration, delegate: HTTPSRedirects(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        do {
            var request = URLRequest(url: try requestURL(for: bootstrap.url))
            request.setValue("application/json", forHTTPHeaderField: "Accept")
            request.setValue("no-cache", forHTTPHeaderField: "Cache-Control")
            let (bytes, response) = try await session.bytes(for: request)
            guard let http = response as? HTTPURLResponse, http.statusCode == 200,
                  http.url?.scheme == "https", response.expectedContentLength <= Int64(maxBytes)
            else { throw VPNError("Сервер обновлений временно недоступен") }
            var data = Data()
            for try await byte in bytes {
                guard data.count < maxBytes else { throw VPNError("Обновление превышает допустимый размер") }
                data.append(byte)
            }
            let update = try verify(data, bootstrap: bootstrap, highestRevision: highestRevision)
            if update.revision > highestRevision, update.profile.connections.contains(where: { $0.builtin == nil }) {
                guard let executable = Bundle.main.url(forResource: "xray", withExtension: nil) else {
                    throw VPNError("Не найдено ядро Xray; обновите приложение")
                }
                try validateExtraConfigs(update.profile, executable: executable)
            }
            return update
        } catch let error as VPNError {
            throw error
        } catch {
            throw VPNError("Не удалось загрузить обновление. Проверьте интернет и повторите попытку")
        }
    }
}
