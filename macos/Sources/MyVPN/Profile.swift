import Foundation

enum VPNProtocol: String, CaseIterable, Identifiable {
    case vlessTcp = "VLESS_TCP"
    case hy2 = "HY2"
    case hy2Obfs = "HY2_OBFS"
    case awg = "AWG"

    var id: String { rawValue }

    var title: String {
        switch self {
        case .vlessTcp: return "VLESS Reality · TCP"
        case .hy2: return "Hysteria2"
        case .hy2Obfs: return "Hysteria2 + Salamander"
        case .awg: return "AmneziaWG"
        }
    }

    var subtitle: String {
        switch self {
        case .vlessTcp: return "Vision, порт 443. Маскировка под HTTPS"
        case .hy2: return "QUIC (как HTTP/3), UDP 443. Быстрый на плохих сетях"
        case .hy2Obfs: return "QUIC с обфускацией — если обычный режут"
        case .awg: return "WireGuard с обфускацией, UDP"
        }
    }

    var usesXray: Bool { self != .awg }
}

/// Профиль сервера в формате `vpnctl profile <имя>`. Храним JSON как есть, поля читаем по пути "vless.uuid".
struct Profile {
    private(set) var json: [String: Any]

    /// Старые сохранённые профили сохраняют ключи сервера, но удалённые режимы игнорируются.
    init(json: [String: Any]) {
        var current = json
        current.removeValue(forKey: "wg")
        current.removeValue(forKey: "relay")
        if var vless = current["vless"] as? [String: Any] {
            vless.removeValue(forKey: "xhttpPort")
            vless.removeValue(forKey: "xhttpPath")
            current["vless"] = vless
        }
        current["version"] = 2
        self.json = current
    }

    func str(_ path: String) -> String {
        var node: Any? = json
        for key in path.split(separator: ".") {
            node = (node as? [String: Any])?[String(key)]
        }
        switch node {
        case let s as String: return s
        case let n as NSNumber: return n.stringValue
        default: return ""
        }
    }

    func int(_ path: String) -> Int { Int(str(path).trimmingCharacters(in: .whitespaces)) ?? 0 }

    var host: String { str("host") }

    var dnsServers: [String] {
        str("dns").split(whereSeparator: { $0 == "," || $0 == " " }).map(String.init)
    }

    /// Копия профиля с изменёнными полями; числовые поля сохраняются числами.
    func with(_ values: [String: String]) -> Profile {
        var copy = json
        for (path, raw) in values {
            guard let field = Fields.byPath[path] else { continue }
            let v = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            Profile.set(&copy, path.split(separator: ".").map(String.init), field.numeric ? (Int(v) ?? 0) as Any : v)
        }
        return Profile(json: copy)
    }

    private static func set(_ dict: inout [String: Any], _ keys: [String], _ value: Any) {
        guard let first = keys.first else { return }
        if keys.count == 1 {
            dict[first] = value
        } else {
            var child = dict[first] as? [String: Any] ?? [:]
            set(&child, Array(keys.dropFirst()), value)
            dict[first] = child
        }
    }

    func serialized() -> String {
        let data = (try? JSONSerialization.data(withJSONObject: json, options: [.sortedKeys])) ?? Data()
        return String(decoding: data, as: UTF8.self)
    }

    static func parse(_ text: String) throws -> Profile {
        let data = Data(text.trimmingCharacters(in: .whitespacesAndNewlines).utf8)
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              obj["host"] != nil, obj["vless"] != nil
        else { throw VPNError("Это не профиль My VPN (нет полей host/vless)") }
        try ProfileValidation.extras(obj["extraXray"])
        return Profile(json: obj)
    }
}

struct Field: Identifiable {
    let path: String
    let label: String
    var numeric = false
    var id: String { path }
}

struct FieldGroup: Identifiable {
    let title: String
    let fields: [Field]
    var id: String { title }
}

enum Fields {
    static let groups: [FieldGroup] = [
        FieldGroup(title: "Сервер", fields: [
            Field(path: "host", label: "Адрес сервера (IP или домен)"),
            Field(path: "dns", label: "DNS внутри туннеля"),
        ]),
        FieldGroup(title: "VLESS + Reality", fields: [
            Field(path: "vless.uuid", label: "UUID"),
            Field(path: "vless.sni", label: "SNI (маскировочный сайт)"),
            Field(path: "vless.publicKey", label: "Public key"),
            Field(path: "vless.shortId", label: "Short ID"),
            Field(path: "vless.fingerprint", label: "Fingerprint"),
            Field(path: "vless.tcpPort", label: "Порт TCP", numeric: true),
        ]),
        FieldGroup(title: "Hysteria2", fields: [
            Field(path: "hy2.port", label: "Порт (UDP)", numeric: true),
            Field(path: "hy2.obfsPort", label: "Порт с Salamander (UDP)", numeric: true),
            Field(path: "hy2.auth", label: "Пароль (auth)"),
            Field(path: "hy2.sni", label: "SNI"),
            Field(path: "hy2.pinSha256", label: "SHA-256 сертификата"),
            Field(path: "hy2.obfsPassword", label: "Пароль Salamander"),
        ]),
        FieldGroup(title: "AmneziaWG", fields: [
            Field(path: "awg.port", label: "Порт (UDP)", numeric: true),
            Field(path: "awg.privateKey", label: "Private key клиента"),
            Field(path: "awg.address", label: "Адрес клиента"),
            Field(path: "awg.mtu", label: "MTU", numeric: true),
            Field(path: "awg.serverPublicKey", label: "Public key сервера"),
            Field(path: "awg.presharedKey", label: "Preshared key"),
            Field(path: "awg.jc", label: "Jc", numeric: true),
            Field(path: "awg.jmin", label: "Jmin", numeric: true),
            Field(path: "awg.jmax", label: "Jmax", numeric: true),
            Field(path: "awg.s1", label: "S1", numeric: true),
            Field(path: "awg.s2", label: "S2", numeric: true),
            Field(path: "awg.s3", label: "S3", numeric: true),
            Field(path: "awg.s4", label: "S4", numeric: true),
            Field(path: "awg.h1", label: "H1"),
            Field(path: "awg.h2", label: "H2"),
            Field(path: "awg.h3", label: "H3"),
            Field(path: "awg.h4", label: "H4"),
            Field(path: "awg.i1", label: "I1"),
        ]),
    ]

    static let byPath: [String: Field] = Dictionary(
        uniqueKeysWithValues: groups.flatMap(\.fields).map { ($0.path, $0) }
    )
}

struct VPNError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

/// Выбор протокола: встроенный режим либо совместимый outbound из проверенного профиля.
struct VPNConnection: Identifiable, Hashable {
    let id: String
    let title: String
    let subtitle: String
    let builtin: VPNProtocol?
    let outbound: [String: Any]?

    init(_ proto: VPNProtocol) {
        id = proto.rawValue
        title = proto.title
        subtitle = proto.subtitle
        builtin = proto
        outbound = nil
    }

    init(id: String, title: String, outbound: [String: Any]) {
        self.id = id
        self.title = title
        subtitle = "Дополнительный режим Xray"
        builtin = nil
        self.outbound = outbound
    }

    var rawValue: String { id }
    var usesXray: Bool { builtin?.usesXray ?? true }
    static func == (lhs: Self, rhs: Self) -> Bool { lhs.id == rhs.id }
    func hash(into hasher: inout Hasher) { hasher.combine(id) }
}

extension Profile {
    var connections: [VPNConnection] {
        VPNProtocol.allCases.map(VPNConnection.init) + ((json["extraXray"] as? [[String: Any]]) ?? []).compactMap { entry in
            guard let id = entry["id"] as? String,
                  let title = entry["title"] as? String,
                  let outbound = entry["outbound"] as? [String: Any] else { return nil }
            return VPNConnection(id: id, title: title, outbound: outbound)
        }
    }
}
