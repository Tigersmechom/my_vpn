import Foundation

enum KillSwitchChecks {
    static func run(profile: Profile, destination: URL) throws {
        for (text, state, protection): (String, VPNState, KillSwitchState) in [
            ("down\nkill-switch off\n", .down, .inactive),
            ("xray utun199\nkill-switch on\n", .up, .active),
            ("awg utun7\nhandshake 1\ntransfer 2 3\nkill-switch on\n", .up, .active),
            ("blocked\nkill-switch on\n", .blocked, .blocked),
            ("down\nkill-switch on\n", .blocked, .blocked),
            ("xray utun199\nkill-switch failed\n", .up, .unavailable),
            ("down\nkill-switch failed\n", .down, .unavailable),
            ("awg utun4\n", .up, .unavailable), // old helper: never claim protection
        ] {
            let parsed = try HelperStatus(text)
            precondition(parsed.state == state && parsed.protection == protection)
        }
        for text in ["", "nonsense", "blocked\nkill-switch off", "down\nkill-switch on\nkill-switch off"] {
            do { _ = try HelperStatus(text); preconditionFailure("Invalid helper status accepted") } catch { }
        }
        for server in profile.servers {
            for connection in server.profile.connections where connection.usesXray {
                var lookedUp: [String] = []
                let config = try Configs.xrayForTunnel(server.profile, connection) { host in
                    lookedUp.append(host)
                    return "203.0.113.99"
                }
                precondition(lookedUp.count == 1)
                precondition(config.ip == "203.0.113.99" && (1...65535).contains(config.port))
                if connection.id == "HY2" || connection.id == "HY2_OBFS" {
                    precondition(config.transport == "udp")
                } else if connection.outbound?["protocol"] as? String == "shadowsocks" {
                    precondition(config.transport == "tcp-udp")
                } else {
                    precondition(config.transport == "tcp")
                }
                let root = try JSONSerialization.jsonObject(with: Data(config.json.utf8)) as! [String: Any]
                let routing = root["routing"] as! [String: Any]
                precondition((routing["rules"] as! [Any]).isEmpty)
                let outbounds = root["outbounds"] as! [[String: Any]]
                precondition(!outbounds.contains { $0["protocol"] as? String == "freedom" })
                let original = try JSONSerialization.jsonObject(with: Data(Configs.xray(server.profile, connection).utf8)) as! [String: Any]
                let originalStream = (original["outbounds"] as! [[String: Any]])[0]["streamSettings"] as? NSDictionary
                precondition(originalStream == outbounds[0]["streamSettings"] as? NSDictionary)
                try config.json.write(to: destination.appendingPathComponent("guarded-\(server.id)-\(connection.id).json"), atomically: true, encoding: .utf8)
            }
        }
        print("Kill switch status, endpoint pinning, TLS preservation and all regional tunnel configs passed")
    }
}
