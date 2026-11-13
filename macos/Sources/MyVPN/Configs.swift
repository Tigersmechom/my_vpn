import Foundation

private let privateNets = [
    "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "fc00::/7", "fe80::/10",
]

enum Configs {
    struct TunnelConfig {
        let json: String
        let ip: String
        let port: Int
        let transport: String
    }

    /// Resolve only the VPN endpoint before arming PF; never grant direct DNS
    /// access to a physical network. Preserve TLS/REALITY serverName and pins.
    static func xrayForTunnel(_ p: Profile, _ connection: VPNConnection,
                              resolve: (String) throws -> String = resolveIPv4) throws -> TunnelConfig {
        let data = Data(xray(p, connection).utf8)
        guard var config = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              var outbounds = config["outbounds"] as? [[String: Any]], !outbounds.isEmpty,
              var settings = outbounds[0]["settings"] as? [String: Any] else {
            throw VPNError("Не удалось определить VPN-соединение для kill switch")
        }
        let stream = outbounds[0]["streamSettings"] as? [String: Any] ?? [:]
        let network = stream["network"] as? String ?? "raw"
        var transport: String
        switch network {
        case "hysteria", "quic", "kcp": transport = "udp"
        case "raw", "tcp", "xhttp", "splithttp", "grpc", "ws", "http", "httpupgrade", "h2": transport = "tcp"
        default: throw VPNError("Kill switch пока не поддерживает транспорт \(network)")
        }
        if outbounds[0]["protocol"] as? String == "shadowsocks", ["raw", "tcp"].contains(network) {
            transport = "tcp-udp"
        }
        var destination = settings
        let arrayKey = settings["vnext"] != nil ? "vnext" : settings["servers"] != nil ? "servers" : nil
        if let arrayKey {
            guard let entries = settings[arrayKey] as? [[String: Any]], entries.count == 1 else {
                throw VPNError("Для kill switch требуется один адрес VPN-сервера")
            }
            destination = entries[0]
        }
        guard let host = destination["address"] as? String, !host.isEmpty,
              let port = destination["port"] as? Int, (1...65535).contains(port) else {
            throw VPNError("В режиме не задан адрес или порт VPN-сервера")
        }
        let ip = try resolve(host)
        destination["address"] = ip
        if let arrayKey { settings[arrayKey] = [destination] } else { settings = destination }
        outbounds[0]["settings"] = settings
        // No private-LAN bypass: all application traffic uses the encrypted
        // outbound. The helper separately permits only loopback and DHCP.
        config["routing"] = ["domainStrategy": "AsIs", "rules": [] as [Any]]
        outbounds.removeAll { $0["tag"] as? String == "direct" }
        config["outbounds"] = outbounds
        let encoded = try JSONSerialization.data(withJSONObject: config, options: [.prettyPrinted])
        return TunnelConfig(json: String(decoding: encoded, as: UTF8.self), ip: ip, port: port, transport: transport)
    }

    static func xray(_ p: Profile, _ connection: VPNConnection) -> String {
        if let builtin = connection.builtin { return xray(p, builtin) }
        return wrap(connection.outbound!)
    }

    /// Outbounds и routing для Xray. TUN-inbound helper добавляет сам.
    static func xray(_ p: Profile, _ proto: VPNProtocol) -> String {
        let proxy = proto == .hy2 || proto == .hy2Obfs
            ? hysteria(p, obfs: proto == .hy2Obfs)
            : vless(p)
        return wrap(proxy)
    }

    private static func wrap(_ outbound: [String: Any]) -> String {
        var proxy = outbound
        proxy["tag"] = "proxy"
        let config: [String: Any] = [
            "outbounds": [
                proxy,
                ["tag": "direct", "protocol": "freedom"],
                ["tag": "block", "protocol": "blackhole"],
            ],
            "routing": [
                "domainStrategy": "AsIs",
                "rules": [["type": "field", "ip": privateNets, "outboundTag": "direct"]],
            ],
        ]
        let data = try! JSONSerialization.data(withJSONObject: config, options: [.prettyPrinted])
        return String(decoding: data, as: UTF8.self)
    }

    /// Hysteria2: QUIC с самоподписанным сертификатом, проверяется по отпечатку SHA-256.
    private static func hysteria(_ p: Profile, obfs: Bool) -> [String: Any] {
        var stream: [String: Any] = [
            "network": "hysteria",
            "hysteriaSettings": ["version": 2, "auth": p.str("hy2.auth")],
            "security": "tls",
            "tlsSettings": [
                "serverName": p.str("hy2.sni"),
                "alpn": ["h3"],
                "pinnedPeerCertSha256": p.str("hy2.pinSha256"),
            ],
        ]
        if obfs {
            stream["finalmask"] = ["udp": [["type": "salamander", "settings": ["password": p.str("hy2.obfsPassword")]]]]
        }
        return [
            "protocol": "hysteria",
            "settings": ["version": 2, "address": p.host, "port": p.int(obfs ? "hy2.obfsPort" : "hy2.port")],
            "streamSettings": stream,
        ]
    }

    private static func vless(_ p: Profile) -> [String: Any] {
        let user: [String: Any] = [
            "address": p.host,
            "port": p.int("vless.tcpPort"),
            "id": p.str("vless.uuid"),
            "encryption": "none",
            // Google и другие приложения могут требовать QUIC на UDP 443.
            "flow": "xtls-rprx-vision-udp443",
        ]

        let fp = p.str("vless.fingerprint")
        let stream: [String: Any] = [
            "network": "raw",
            "security": "reality",
            "realitySettings": [
                "serverName": p.str("vless.sni"),
                "fingerprint": fp.isEmpty ? "chrome" : fp,
                "publicKey": p.str("vless.publicKey"),
                "shortId": p.str("vless.shortId"),
                "spiderX": "/",
            ],
        ]
        return ["protocol": "vless", "settings": user, "streamSettings": stream]
    }

    struct AWG {
        let conf: String
        let address: String
        let mtu: Int
    }

    /// Ключи AmneziaWG для `awg setconf`; маршруты и DNS настраивает helper.
    static func amnezia(_ p: Profile, endpointIP: String) -> AWG {
        var lines = ["[Interface]", "PrivateKey = \(p.str("awg.privateKey"))"]
        for k in ["jc", "jmin", "jmax", "s1", "s2", "s3", "s4"] {
            let v = p.int("awg.\(k)")
            if v > 0 { lines.append("\(k.prefix(1).uppercased() + k.dropFirst()) = \(v)") }
        }
        for k in ["h1", "h2", "h3", "h4", "i1"] {
            let v = p.str("awg.\(k)")
            if !v.isEmpty { lines.append("\(k.uppercased()) = \(v)") }
        }
        lines += ["", "[Peer]", "PublicKey = \(p.str("awg.serverPublicKey"))"]
        let psk = p.str("awg.presharedKey")
        if !psk.isEmpty { lines.append("PresharedKey = \(psk)") }
        lines += [
            "Endpoint = \(endpointIP):\(p.int("awg.port"))",
            "AllowedIPs = 0.0.0.0/0",
            "PersistentKeepalive = 25",
        ]
        let mtu = p.int("awg.mtu")
        return AWG(conf: lines.joined(separator: "\n") + "\n", address: p.str("awg.address"),
                   mtu: mtu > 0 ? mtu : 1280)
    }

    /// IPv4 сервера: helper прокладывает маршрут до него мимо туннеля, поэтому нужен IP, а не домен.
    static func resolveIPv4(_ host: String) throws -> String {
        var hints = addrinfo(ai_flags: 0, ai_family: AF_INET, ai_socktype: SOCK_DGRAM,
                             ai_protocol: 0, ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &res) == 0, let first = res else {
            throw VPNError("Не удалось найти адрес сервера \(host)")
        }
        defer { freeaddrinfo(res) }
        var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        let sin = first.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
        var addr = sin.sin_addr
        inet_ntop(AF_INET, &addr, &buf, socklen_t(INET_ADDRSTRLEN))
        return String(cString: buf)
    }
}
