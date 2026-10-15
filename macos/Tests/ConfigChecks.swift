import Foundation

@main
struct ConfigChecks {
    static func main() throws {
        let source = URL(fileURLWithPath: CommandLine.arguments[1])
        let destination = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
        var profile = try Profile.parse(String(contentsOf: source))
        if source.lastPathComponent == "example.json" {
            var fixture = profile.json
            fixture["client"] = "mac"
            profile = Profile(json: fixture)
        }
        precondition(Set(VPNProtocol.allCases.map(\.rawValue)) == ["VLESS_TCP", "HY2", "HY2_OBFS", "AWG"])

        // Migration must preserve current credentials and never reuse a retired relay.
        var legacy = profile.json
        legacy["version"] = 1
        legacy["relay"] = ["host": "192.0.2.5"]
        legacy["wg"] = ["privateKey": "retired"]
        var vless = legacy["vless"] as! [String: Any]
        vless["xhttpPort"] = 8443
        vless["xhttpPath"] = "/retired"
        legacy["vless"] = vless
        let legacyJSON = String(decoding: try JSONSerialization.data(withJSONObject: legacy), as: UTF8.self)
        let migrated = try Profile.parse(legacyJSON)
        precondition(migrated.json["wg"] == nil && migrated.json["relay"] == nil)
        precondition(migrated.str("vless.xhttpPort").isEmpty && migrated.str("vless.xhttpPath").isEmpty)
        precondition(migrated.host == profile.host)
        precondition(migrated.str("vless.uuid") == profile.str("vless.uuid"))
        precondition(migrated.str("awg.privateKey") == profile.str("awg.privateKey"))

        let suite = "app.myvpn.config-check.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        defaults.set(legacyJSON, forKey: "profile")
        defaults.set(true, forKey: "useRelay")
        for removed in ["WG", "VLESS_XHTTP"] {
            defaults.set(removed, forKey: "protocol")
            let store = Store(defaults: defaults)
            precondition(store.selectedConnection.builtin == .vlessTcp)
            precondition(defaults.string(forKey: "protocol") == VPNProtocol.vlessTcp.rawValue)
            precondition(defaults.object(forKey: "useRelay") == nil)
            precondition(store.profile.json["relay"] == nil)
            precondition(store.profile.host == profile.host)
        }
        let store = Store(defaults: defaults)
        let direct = SpeedResult(protocolRaw: "HY2", time: 1, pingMs: 5, downMbps: 1, upMbps: 1, exitIp: "192.0.2.1")
        let oldRelay = SpeedResult(protocolRaw: "HY2", time: 2, pingMs: 5, downMbps: 1, upMbps: 1, exitIp: "192.0.2.1", viaRelay: true)
        let retired = SpeedResult(protocolRaw: "WG", time: 3, pingMs: 5, downMbps: 1, upMbps: 1, exitIp: "192.0.2.1")
        store.saveResults([direct, oldRelay, retired])
        precondition(store.results().count == 1 && store.results().first?.time == direct.time)

        for proto in VPNProtocol.allCases where proto.usesXray {
            let config = Configs.xray(profile, proto)
            let object = try JSONSerialization.jsonObject(with: Data(config.utf8)) as! [String: Any]
            let outbounds = object["outbounds"] as! [[String: Any]]
            let proxy = outbounds[0]
            let settings = proxy["settings"] as! [String: Any]
            let stream = proxy["streamSettings"] as! [String: Any]
            precondition(settings["address"] as? String == profile.host)
            if proto == .vlessTcp {
                precondition(settings["port"] as? Int == profile.int("vless.tcpPort"))
                precondition(settings["id"] as? String == profile.str("vless.uuid"))
                precondition(settings["flow"] as? String == "xtls-rprx-vision")
                precondition(stream["network"] as? String == "raw" && stream["security"] as? String == "reality")
                precondition(stream["xhttpSettings"] == nil)
                let reality = stream["realitySettings"] as! [String: Any]
                precondition(reality["publicKey"] as? String == profile.str("vless.publicKey"))
            } else {
                precondition(settings["port"] as? Int == profile.int(proto == .hy2 ? "hy2.port" : "hy2.obfsPort"))
                let hysteria = stream["hysteriaSettings"] as! [String: Any]
                let tls = stream["tlsSettings"] as! [String: Any]
                precondition(hysteria["version"] as? Int == 2)
                precondition(hysteria["auth"] as? String == profile.str("hy2.auth"))
                precondition(tls["pinnedPeerCertSha256"] as? String == profile.str("hy2.pinSha256"))
                precondition(tls["allowInsecure"] == nil)
                if proto == .hy2Obfs {
                    let finalmask = stream["finalmask"] as! [String: Any]
                    let mask = (finalmask["udp"] as! [[String: Any]])[0]
                    precondition(mask["type"] as? String == "salamander")
                    precondition((mask["settings"] as! [String: Any])["password"] as? String == profile.str("hy2.obfsPassword"))
                } else {
                    precondition(stream["finalmask"] == nil)
                }
            }
            let file = destination.appendingPathComponent("\(proto.rawValue).json")
            try config.write(to: file, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        }
        let awg = Configs.amnezia(profile, endpointIP: "192.0.2.8")
        precondition(awg.conf.contains("PrivateKey = \(profile.str("awg.privateKey"))\n"))
        precondition(awg.conf.contains("PublicKey = \(profile.str("awg.serverPublicKey"))\n"))
        precondition(awg.conf.contains("Endpoint = 192.0.2.8:\(profile.int("awg.port"))\n"))
        precondition(awg.address == profile.str("awg.address"))
        precondition(awg.mtu == profile.int("awg.mtu"))
        print("Protocol, credential, pin and legacy migration checks passed")
        try UpdateChecks.run(profile: profile, output: destination, source: source)
    }
}
