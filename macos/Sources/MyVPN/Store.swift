import Foundation

struct SpeedResult: Codable, Identifiable {
    var id: Double { time }
    let protocolRaw: String
    let time: Double
    let pingMs: Int
    let downMbps: Double
    let upMbps: Double
    let exitIp: String
    // Только для отбрасывания старых замеров через удалённый посредник.
    var viaRelay: Bool? = false
    var connectionTitle: String? = nil

    var proto: VPNProtocol? { VPNProtocol(rawValue: protocolRaw) }
    var label: String { connectionTitle ?? proto?.title ?? protocolRaw }
}

/// Настройки: текущий профиль, выбранный протокол и история замеров.
final class Store {
    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        defaults.removeObject(forKey: "useRelay")
        if let saved = defaults.string(forKey: "profile"), let migrated = try? Profile.parse(saved) {
            defaults.set(migrated.serialized(), forKey: "profile")
        }
        if let raw = defaults.string(forKey: "protocol"), !profile.connections.contains(where: { $0.id == raw }) {
            defaults.set(VPNProtocol.vlessTcp.rawValue, forKey: "protocol")
        }
    }

    let defaultProfile: Profile = {
        guard let url = Bundle.main.url(forResource: "default_profile", withExtension: "json"),
              let text = try? String(contentsOf: url),
              let p = try? Profile.parse(text)
        else { return Profile(json: ["host": "", "vless": [String: Any]()]) }
        return p
    }()

    // Профиль и защита от отката сохраняются одним значением UserDefaults.
    private var state: [String: Any] {
        guard let data = defaults.data(forKey: "profileState"),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [:] }
        return object
    }

    private func storedProfile(_ object: Any?) -> Profile? {
        guard let object, let data = try? JSONSerialization.data(withJSONObject: object) else { return nil }
        return try? Profile.parse(String(decoding: data, as: UTF8.self))
    }

    var profile: Profile {
        get {
            storedProfile(state["profile"])
                ?? defaults.string(forKey: "profile").flatMap { try? Profile.parse($0) }
                ?? defaultProfile
        }
        set {
            var next = state
            next["profile"] = newValue.json
            if let data = try? JSONSerialization.data(withJSONObject: next) {
                defaults.set(data, forKey: "profileState")
            }
        }
    }

    var highestRevision: Int { state["revision"] as? Int ?? 0 }
    var resetTarget: Profile { storedProfile(state["remoteProfile"]) ?? defaultProfile }
    func resetProfile() { profile = resetTarget }

    func applyRemote(_ profile: Profile, revision: Int) throws {
        guard revision > highestRevision else { throw VPNError("Повторное или устаревшее обновление") }
        let next: [String: Any] = ["profile": profile.json, "remoteProfile": profile.json, "revision": revision]
        let data = try JSONSerialization.data(withJSONObject: next, options: [.sortedKeys])
        defaults.set(data, forKey: "profileState")
    }

    var selectedConnection: VPNConnection {
        get {
            let id = defaults.string(forKey: "protocol") ?? VPNProtocol.vlessTcp.rawValue
            return profile.connections.first { $0.id == id } ?? VPNConnection(.vlessTcp)
        }
        set { defaults.set(newValue.id, forKey: "protocol") }
    }

    func results() -> [SpeedResult] {
        guard let data = defaults.data(forKey: "results") else { return [] }
        let saved = (try? JSONDecoder().decode([SpeedResult].self, from: data)) ?? []
        let ids = Set(profile.connections.map(\.id))
        return saved.filter { ids.contains($0.protocolRaw) && $0.viaRelay != true }
    }

    func saveResults(_ list: [SpeedResult]) {
        defaults.set(try? JSONEncoder().encode(Array(list.prefix(30))), forKey: "results")
    }
}
