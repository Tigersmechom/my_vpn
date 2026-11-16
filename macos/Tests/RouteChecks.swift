import Foundation

enum RouteChecks {
    static func run(profile: Profile, output: URL) throws {
        var base = profile.json
        base.removeValue(forKey: "routes")
        base.removeValue(forKey: "additionalServers")
        base.removeValue(forKey: "extraXray")
        base["enabledProtocols"] = ["HY2", "HY2_OBFS", "AWG"]
        var poland = base
        poland["host"] = "203.0.113.90"
        var relay = base
        relay["host"] = "203.0.113.90"
        relay["exitHost"] = base["host"]
        var hy2 = relay["hy2"] as! [String: Any]
        hy2["port"] = 10443; hy2["obfsPort"] = 10444
        relay["hy2"] = hy2
        var awg = relay["awg"] as! [String: Any]
        awg["port"] = 10445
        relay["awg"] = awg
        var catalog = base
        let entries: [[String: Any]] = [
            ["id": "pl", "title": "Польша", "profile": poland],
            ["id": "pl-fi", "title": "Польша → Финляндия", "profile": relay],
        ]
        catalog["routes"] = entries
        let parsed = try ProfileValidation.profile(catalog)
        precondition(parsed.connections.count == 9 && Set(parsed.connections.map(\.id)).count == 9)
        precondition(parsed.connections.filter { !$0.usesXray }.count == 3)
        for connection in parsed.connections {
            let endpoint = parsed.connectionProfile(connection)
            if connection.routeID != nil { precondition(endpoint.host == "203.0.113.90") }
            if connection.usesXray {
                let config = Configs.xray(parsed, connection)
                let object = try JSONSerialization.jsonObject(with: Data(config.utf8)) as! [String: Any]
                let proxy = (object["outbounds"] as! [[String: Any]])[0]
                precondition((proxy["settings"] as! [String: Any])["address"] as? String == endpoint.host)
                let stream = proxy["streamSettings"] as! [String: Any]
                precondition((stream["tlsSettings"] as! [String: Any])["pinnedPeerCertSha256"] as? String == endpoint.str("hy2.pinSha256"))
                if connection.routeID == "pl-fi" {
                    precondition(endpoint.str("hy2.pinSha256") == profile.str("hy2.pinSha256"))
                    precondition(endpoint.str("hy2.auth") == profile.str("hy2.auth"))
                }
                try config.write(to: output.appendingPathComponent("routes-\(connection.id).json"), atomically: true, encoding: .utf8)
            } else {
                let config = Configs.amnezia(endpoint, endpointIP: endpoint.host)
                precondition(config.conf.contains("Endpoint = \(endpoint.host):\(endpoint.int("awg.port"))\n"))
                if connection.routeID == "pl-fi" {
                    precondition(endpoint.str("awg.privateKey") == profile.str("awg.privateKey"))
                    precondition(endpoint.int("awg.port") == 10445)
                }
            }
        }
        for bad: Any in [[], [entries[0], entries[0]], [["id": "bad", "title": "bad\nname", "profile": poland]],
                         [["id": "nested", "title": "Nested", "profile": catalog]], [["id": "bad", "title": "Missing", "profile": ["client": "android"]]]] {
            var invalid = catalog; invalid["routes"] = bad
            do { _ = try ProfileValidation.profile(invalid); preconditionFailure("Invalid route accepted") } catch { }
        }
        print("Nine route choices, AWG backend selection, relay endpoints, retained pins and bounded route validation passed")
    }
}
