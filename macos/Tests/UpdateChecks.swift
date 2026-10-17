import Foundation
import CryptoKit

enum UpdateChecks {
    static func run(profile: Profile, publishedProfile: Profile, output: URL, source: URL, repository: URL) throws {
        precondition(profile.connections.count == VPNProtocol.allCases.count)
        let key = Data((0..<32).map(UInt8.init))
        let bootstrap = UpdateBootstrap(client: "mac", url: URL(string: "https://example.com/mac.json")!, key: key, minRevision: 1)
        func encoded(_ profileJSON: [String: Any], revision: Int = 1, client: String = "mac", innerRevision: Int? = nil) throws -> Data {
            let payload: [String: Any] = ["schema": 1, "client": client, "revision": innerRevision ?? revision, "profile": profileJSON]
            let plaintext = try JSONSerialization.data(withJSONObject: payload)
            let nonce = try AES.GCM.Nonce(data: Data(repeating: 5, count: 12))
            let sealed = try AES.GCM.seal(plaintext, using: SymmetricKey(data: key), nonce: nonce,
                                          authenticating: Data("myvpn-update-v1\n\(client)\n\(revision)".utf8))
            let envelope: [String: Any] = ["format": "myvpn-update-v1", "client": client, "revision": revision,
                                         "nonce": nonce.withUnsafeBytes { Data($0).base64EncodedString() },
                                         "ciphertext": (sealed.ciphertext + sealed.tag).base64EncodedString()]
            return try JSONSerialization.data(withJSONObject: envelope)
        }
        func rejects(_ data: Data, highest: Int = 0, using: UpdateBootstrap? = nil) {
            do {
                _ = try RemoteUpdates.verify(data, bootstrap: using ?? bootstrap, highestRevision: highest)
                preconditionFailure("Invalid update was accepted")
            } catch { }
        }
        let first = try encoded(profile.json)
        let verified = try RemoteUpdates.verify(first, bootstrap: bootstrap, highestRevision: 0)
        precondition(verified.revision == 1 && verified.profile.host == profile.host)
        _ = try RemoteUpdates.verify(first, bootstrap: bootstrap, highestRevision: 1) // idempotent refresh
        rejects(first, highest: 2)
        rejects(first, using: UpdateBootstrap(client: "mac", url: bootstrap.url, key: key, minRevision: 2))
        rejects(first, using: UpdateBootstrap(client: "mac", url: bootstrap.url, key: Data(repeating: 0, count: 32), minRevision: 1))
        rejects(try encoded(profile.json, client: "android"))
        var wrongProfileClient = profile.json
        wrongProfileClient["client"] = "android"
        rejects(try encoded(wrongProfileClient))
        rejects(try encoded(profile.json, innerRevision: 2))
        var envelope = try JSONSerialization.jsonObject(with: first) as! [String: Any]
        var corrupted = Data(base64Encoded: envelope["ciphertext"] as! String)!
        corrupted[0] ^= 1
        envelope["ciphertext"] = corrupted.base64EncodedString()
        rejects(try JSONSerialization.data(withJSONObject: envelope))
        envelope = try JSONSerialization.jsonObject(with: first) as! [String: Any]
        envelope["revision"] = 2 // authenticated metadata cannot be relabelled
        rejects(try JSONSerialization.data(withJSONObject: envelope))
        rejects(Data(repeating: 32, count: RemoteUpdates.maxBytes + 1))
        var incomplete = profile.json
        incomplete.removeValue(forKey: "awg")
        rejects(try encoded(incomplete))

        let extra: [String: Any] = ["id": "custom-tls", "title": "Резерв TLS", "outbound": [
            "protocol": "trojan", "settings": ["servers": [["address": "example.com", "port": 443, "password": "test-only"]]],
            "streamSettings": ["network": "raw", "security": "tls", "tlsSettings": ["serverName": "example.com"]],
        ]]
        var extended = profile.json
        extended["extraXray"] = [extra]
        let update = try RemoteUpdates.verify(encoded(extended, revision: 2), bootstrap: bootstrap, highestRevision: 1)
        precondition(update.profile.connections.count == 5)
        try RemoteUpdates.validateExtraConfigs(update.profile, executable: repository.appendingPathComponent("macos/vendor/xray"))
        let custom = update.profile.connections.last!
        precondition(custom.id == "custom-tls" && custom.usesXray && custom.builtin == nil)
        let config = Configs.xray(update.profile, custom)
        let object = try JSONSerialization.jsonObject(with: Data(config.utf8)) as! [String: Any]
        precondition((object["outbounds"] as! [[String: Any]])[0]["tag"] as? String == "proxy")
        try config.write(to: output.appendingPathComponent("custom-tls.json"), atomically: true, encoding: .utf8)
        for forbidden in ["certificateFile", "keyFile", "masterKeyLog", "sslKeyLogFile", "sockopt", "proxySettings", "sendThrough", "script"] {
            var bad = extra
            var outbound = bad["outbound"] as! [String: Any]
            outbound["streamSettings"] = [forbidden: "forbidden"]
            bad["outbound"] = outbound
            var candidate = profile.json
            candidate["extraXray"] = [bad]
            rejects(try encoded(candidate))
        }
        var insecure = extra
        var outbound = insecure["outbound"] as! [String: Any]
        outbound["streamSettings"] = ["tlsSettings": ["allowInsecure": true]]
        insecure["outbound"] = outbound
        var candidate = profile.json
        candidate["extraXray"] = [insecure]
        rejects(try encoded(candidate))
        for invalidFlag: Any in ["true", "false", 0, 1] {
            outbound["streamSettings"] = ["tlsSettings": ["allowInsecure": invalidFlag]]
            insecure["outbound"] = outbound
            candidate["extraXray"] = [insecure]
            rejects(try encoded(candidate))
        }
        candidate["extraXray"] = [extra, extra]
        rejects(try encoded(candidate))
        candidate["extraXray"] = (0..<9).map { index -> [String: Any] in
            var entry = extra; entry["id"] = "custom-\(index)"; return entry
        }
        rejects(try encoded(candidate))

        let suite = "app.myvpn.update-check.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let store = Store(defaults: defaults)
        store.profile = profile
        let activeSnapshot = store.profile
        try store.applyRemote(update.profile, revision: 2)
        store.selectedConnection = custom
        precondition(store.highestRevision == 2 && store.profile.connections.count == 5)
        precondition(activeSnapshot.connections.count == 4) // running connections keep their snapshot
        precondition(Store(defaults: defaults).selectedConnection.id == custom.id)
        do { try store.applyRemote(profile, revision: 1); preconditionFailure("Rollback saved") } catch { }
        precondition(store.highestRevision == 2 && store.profile.connections.count == 5)
        store.profile = profile.with(["host": "edited.example.com"])
        store.resetProfile()
        precondition(store.highestRevision == 2 && store.profile.connections.count == 5)

        // Python publisher -> real CryptoKit interoperability, when the private bootstrap exists.
        let bootstrapURL = repository.appendingPathComponent("config/mac-update.json")
        let envelopeURL = repository.appendingPathComponent("updates/mac.json")
        if source.lastPathComponent == "mac.json", FileManager.default.fileExists(atPath: bootstrapURL.path), FileManager.default.fileExists(atPath: envelopeURL.path) {
            let realBootstrap = try UpdateBootstrap.parse(Data(contentsOf: bootstrapURL))
            let realUpdate = try RemoteUpdates.verify(Data(contentsOf: envelopeURL), bootstrap: realBootstrap, highestRevision: 0)
            precondition(realUpdate.profile.serialized() == publishedProfile.serialized())
            try RemoteUpdates.validateExtraConfigs(realUpdate.profile, executable: repository.appendingPathComponent("macos/vendor/xray"))
            let realSuite = "app.myvpn.published-check.\(UUID().uuidString)"
            let realDefaults = UserDefaults(suiteName: realSuite)!
            defer { realDefaults.removePersistentDomain(forName: realSuite) }
            let realStore = Store(defaults: realDefaults)
            try realStore.applyRemote(realUpdate.profile, revision: realUpdate.revision)
            precondition(realStore.profile.serialized() == publishedProfile.serialized())
            for connection in publishedProfile.connections {
                realStore.selectedConnection = connection
                precondition(Store(defaults: realDefaults).selectedConnection.id == connection.id)
            }
            print("Python publisher / CryptoKit interoperability passed for the complete published profile")
        }
        print("Update authentication, rollback, atomic state and custom-mode checks passed")
    }
}
