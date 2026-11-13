import Foundation

enum RegionChecks {
    static func run(profile: Profile) throws {
        var secondary = profile.json
        secondary.removeValue(forKey: "additionalServers")
        secondary["host"] = "203.0.113.21"
        secondary["enabledProtocols"] = ["HY2", "HY2_OBFS", "AWG"]
        secondary.removeValue(forKey: "extraXray")
        var catalog = profile.json
        catalog["serverTitle"] = "Финляндия"
        catalog["additionalServers"] = [["id": "us", "title": "США", "profile": secondary]]
        let validated = try ProfileValidation.profile(catalog)
        precondition(validated.servers.count == 2)
        precondition(validated.servers[1].profile.connections.map(\.id) == ["HY2", "HY2_OBFS", "AWG"])
        precondition(validated.servers[0].profile.host == profile.host)
        let suite = "app.myvpn.regions-check.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let store = Store(defaults: defaults)
        store.profile = validated
        store.selectedConnection = VPNConnection(.vlessTcp)
        store.selectedServer = validated.servers[1]
        precondition(store.selectedConnection.id == "HY2")
        precondition(Store(defaults: defaults).selectedServer.id == "us")
        let snapshot = store.selectedServer.profile
        store.editingProfile = snapshot.with(["host": "203.0.113.22"])
        precondition(store.profile.host == profile.host)
        precondition(store.selectedServer.profile.host == "203.0.113.22")
        precondition(snapshot.host == "203.0.113.21")
        var regionalResult = SpeedResult(protocolRaw: "HY2", time: 1, pingMs: 5, downMbps: 1, upMbps: 1, exitIp: "203.0.113.21")
        regionalResult.serverId = "us"
        store.saveResults([regionalResult])
        store.selectedServer = store.profile.servers[0]
        precondition(store.results().isEmpty)
        store.saveResults([SpeedResult(protocolRaw: "HY2", time: 2, pingMs: 9, downMbps: 2, upMbps: 1, exitIp: "203.0.113.20")])
        store.selectedServer = store.profile.servers[1]
        precondition(store.results().count == 1 && store.results()[0].serverId == "us")
        var replacement = catalog
        replacement.removeValue(forKey: "additionalServers")
        try store.applyRemote(try ProfileValidation.profile(replacement), revision: 100)
        precondition(store.selectedServer.id == "primary")
        precondition(store.selectedConnection.id == "HY2")
        for value: Any in [[], ["AWG", "AWG"], ["INVALID"], [true]] {
            var invalid = secondary
            invalid["enabledProtocols"] = value
            do { _ = try ProfileValidation.profile(invalid); preconditionFailure("Bad protocol list accepted") } catch { }
        }
        for invalidEntries: Any in [
            [["id": "primary", "title": "bad", "profile": secondary]],
            [["id": "us", "title": "bad", "profile": catalog]],
            [["id": "us", "title": "bad", "profile": secondary], ["id": "us", "title": "bad", "profile": secondary]],
            [["id": "us", "title": "bad\nname", "profile": secondary]],
            [["id": "us", "title": "bad", "profile": ["client": "android"]]],
        ] {
            var invalid = catalog
            invalid["additionalServers"] = invalidEntries
            do { _ = try ProfileValidation.profile(invalid); preconditionFailure("Bad catalog accepted") } catch { }
        }
        print("Region selection, protocol filtering, isolated history, update fallback and catalog validation passed")
    }
}
