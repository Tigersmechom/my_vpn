import Foundation
import CoreFoundation

enum ProfileValidation {
    static func integer(_ value: Any?, minimum: Int = 1, maximum: Int = 2_147_483_647) throws -> Int {
        guard let n = value as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID(),
              n.doubleValue.isFinite, n.doubleValue.rounded() == n.doubleValue,
              n.doubleValue >= Double(minimum), n.doubleValue <= Double(maximum)
        else { throw VPNError("Некорректное целое число в обновлении") }
        return n.intValue
    }

    static func profile(_ object: Any) throws -> Profile {
        guard let json = object as? [String: Any], try integer(json["version"]) == 2 else {
            throw VPNError("Неподдерживаемая версия профиля; обновите приложение")
        }
        let p = Profile(json: json)
        func require(_ path: String, pattern: String? = nil) throws {
            let value = p.str(path)
            guard !value.isEmpty, value.count <= 8192,
                  !value.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains),
                  pattern == nil || value.range(of: pattern!, options: .regularExpression) != nil
            else { throw VPNError("Профиль содержит некорректное поле \(path)") }
        }
        try require("host", pattern: "^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
        try require("dns")
        guard !p.dnsServers.isEmpty, p.dnsServers.allSatisfy({ $0.range(of: "^[0-9a-fA-F:.]+$", options: .regularExpression) != nil }) else {
            throw VPNError("Некорректные DNS в профиле")
        }
        guard UUID(uuidString: p.str("vless.uuid")) != nil else { throw VPNError("Некорректный UUID в профиле") }
        try require("vless.sni")
        try require("vless.publicKey", pattern: "^[A-Za-z0-9_-]{43}$")
        try require("vless.shortId", pattern: "^(?:[0-9a-fA-F]{2}){1,8}$")
        for path in ["vless.tcpPort", "hy2.port", "hy2.obfsPort", "awg.port"] {
            let parts = path.split(separator: ".")
            _ = try integer((json[String(parts[0])] as? [String: Any])?[String(parts[1])], maximum: 65535)
        }
        for path in ["hy2.auth", "hy2.sni", "hy2.obfsPassword", "awg.address"] { try require(path) }
        try require("hy2.pinSha256", pattern: "^[0-9a-fA-F]{64}$")
        for path in ["awg.privateKey", "awg.serverPublicKey", "awg.presharedKey"] {
            guard Data(base64Encoded: p.str(path))?.count == 32 else { throw VPNError("Некорректный ключ AmneziaWG") }
        }
        guard let awg = json["awg"] as? [String: Any] else { throw VPNError("Нет настроек AmneziaWG") }
        _ = try integer(awg["mtu"], minimum: 576, maximum: 9000)
        for key in ["jc", "jmin", "jmax", "s1", "s2", "s3", "s4"] {
            _ = try integer(awg[key], minimum: 0)
        }
        for key in ["h1", "h2", "h3", "h4"] { try require("awg.\(key)") }
        try extras(json["extraXray"])
        return p
    }

    static func extras(_ value: Any?) throws {
        guard let value else { return }
        guard let entries = value as? [[String: Any]], entries.count <= 8 else {
            throw VPNError("Некорректный список дополнительных режимов Xray")
        }
        var ids = Set<String>()
        for entry in entries {
            guard let id = entry["id"] as? String,
                  id.range(of: "^custom-[A-Za-z0-9_-]{1,48}$", options: .regularExpression) != nil,
                  ids.insert(id).inserted,
                  let title = entry["title"] as? String, !title.trimmingCharacters(in: .whitespaces).isEmpty,
                  title.count <= 80, !title.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains),
                  let outbound = entry["outbound"] as? [String: Any],
                  Set(outbound.keys).isSubset(of: ["protocol", "settings", "streamSettings", "mux"]),
                  let proto = outbound["protocol"] as? String,
                  ["vless", "hysteria", "trojan", "vmess", "shadowsocks"].contains(proto),
                  outbound["settings"] is [String: Any]
            else { throw VPNError("Неподдерживаемый дополнительный режим; обновите приложение") }
            if proto == "hysteria" {
                guard let settings = outbound["settings"] as? [String: Any], try integer(settings["version"]) == 2 else {
                    throw VPNError("Дополнительный режим Hysteria должен использовать версию 2")
                }
            }
            try safeObject(outbound, depth: 0)
        }
    }

    private static func safeObject(_ value: Any, depth: Int) throws {
        guard depth <= 16 else { throw VPNError("Слишком сложная конфигурация Xray") }
        if let object = value as? [String: Any] {
            let blocked: Set<String> = ["log", "masterkeylog", "sockopt", "proxysettings", "sendthrough", "dialerproxy",
                                        "inbounds", "outbounds", "routing", "dns", "api", "stats", "policy", "includes",
                                        "script", "exec", "command"]
            for (key, child) in object {
                let lower = key.lowercased()
                if lower == "allowinsecure" {
                    guard let flag = child as? NSNumber, CFGetTypeID(flag) == CFBooleanGetTypeID(), !flag.boolValue else {
                        throw VPNError("Дополнительный режим не может отключать проверку TLS")
                    }
                }
                guard !blocked.contains(lower), !lower.hasSuffix("file"), !lower.hasSuffix("filename"), !lower.hasSuffix("filepath") else {
                    throw VPNError("Недопустимое поле в дополнительном режиме Xray")
                }
                try safeObject(child, depth: depth + 1)
            }
        } else if let array = value as? [Any] {
            for child in array { try safeObject(child, depth: depth + 1) }
        }
    }
}
