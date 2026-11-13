import Foundation
import SwiftUI

@MainActor
final class VPNManager: ObservableObject {
    let store = Store()

    @Published var state: VPNState = .down
    @Published var activeProtocol: VPNConnection?
    @Published var activeServerHost: String?
    @Published var activeServerTitle: String?
    @Published var selectedServerId: String
    @Published var selected: VPNConnection
    @Published var since: Date?
    @Published var error: String?
    @Published var helperReady = false
    @Published var killSwitch: KillSwitchState = .inactive
    @Published var installingHelper = false
    @Published var results: [SpeedResult]
    @Published var updatingConfiguration = false
    @Published var configurationMessage: String?
    private let updateBootstrap = UpdateBootstrap.bundled
    private var refreshing = false
    private var changingConnection = false

    var connections: [VPNConnection] { store.selectedServer.profile.connections }
    var servers: [VPNServer] { store.profile.servers }
    var canUpdateConfiguration: Bool { updateBootstrap != nil }

    func reloadProfileChoices() {
        selectedServerId = store.selectedServer.id
        selected = store.selectedConnection
        results = store.results()
    }

    func updateConfiguration() async {
        guard !updatingConfiguration, let bootstrap = updateBootstrap else { return }
        updatingConfiguration = true
        configurationMessage = "Проверяю обновления…"
        defer { updatingConfiguration = false }
        do {
            let update = try await RemoteUpdates.fetch(bootstrap: bootstrap, highestRevision: store.highestRevision)
            if update.revision == store.highestRevision {
                configurationMessage = "У вас актуальная конфигурация (\(update.revision))"
                return
            }
            try store.applyRemote(update.profile, revision: update.revision)
            reloadProfileChoices()
            configurationMessage = "Конфигурация \(update.revision) сохранена. Применится при следующем подключении"
        } catch {
            configurationMessage = error.localizedDescription
        }
    }

    private var runDir: URL {
        let dir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("MyVPN/run", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        return dir
    }

    init() {
        selectedServerId = store.selectedServer.id
        selected = store.selectedConnection
        results = store.results()
        Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                await self.refresh()
                try? await Task.sleep(nanoseconds: 3_000_000_000)
            }
        }
    }

    /// Синхронизация с реальным состоянием (VPN мог остаться поднятым с прошлого запуска).
    func refresh() async {
        guard !refreshing, !changingConnection, !installingHelper else { return }
        refreshing = true
        defer { refreshing = false }
        helperReady = await background { Helper.isReady }
        guard await background({ FileManager.default.isExecutableFile(atPath: Helper.installedPath) }) else { return }
        do {
            let status = try HelperStatus(try await background { try Helper.run(["status"]) })
            guard !changingConnection, !installingHelper else { return }
            state = status.state
            killSwitch = status.protection
        } catch {
            killSwitch = .unavailable
            self.error = "Не удалось проверить состояние сети: \(error.localizedDescription)"
            return
        }
        if state == .up {
            since = since ?? Date()
            if activeProtocol == nil { activeProtocol = selected }
        } else {
            activeProtocol = nil
            since = nil
        }
    }

    func installHelper() async {
        guard state == .down, !changingConnection, !installingHelper, killSwitch == .inactive else { return }
        installingHelper = true
        error = nil
        do {
            try await background { try Helper.install() }
        } catch {
            self.error = error.localizedDescription
        }
        installingHelper = false
        await refresh()
    }

    func select(_ proto: VPNConnection) {
        guard !changingConnection, !installingHelper, state != .connecting, proto != selected else { return }
        selected = proto
        store.selectedConnection = proto
        if state == .up { Task { await connect() } }
    }

    func selectServer(_ id: String) {
        guard !changingConnection, !installingHelper, state == .down || state == .blocked,
              let server = servers.first(where: { $0.id == id }) else { return }
        store.selectedServer = server
        reloadProfileChoices()
    }

    func toggle() {
        Task { state == .down || state == .blocked ? await connect() : await disconnect() }
    }

    func connect() async {
        guard helperReady, !changingConnection, !installingHelper else { return }
        changingConnection = true
        let profile = store.selectedServer.profile
        let proto = profile.connections.first { $0.id == selected.id } ?? profile.connections[0]
        selected = proto
        store.selectedConnection = proto
        error = nil
        state = .connecting
        activeProtocol = proto
        activeServerHost = profile.host
        activeServerTitle = store.selectedServer.title
        do {
            let dir = runDir
            try await background {
                let dns = profile.dnsServers.joined(separator: ",")
                if proto.usesXray {
                    let config = try Configs.xrayForTunnel(profile, proto)
                    let file = dir.appendingPathComponent("xray.json")
                    try config.json.write(to: file, atomically: true, encoding: .utf8)
                    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
                    try Helper.run(["start-xray", file.path, dns, config.ip, String(config.port), config.transport])
                } else {
                    let ip = try Configs.resolveIPv4(profile.host)
                    let awg = Configs.amnezia(profile, endpointIP: ip)
                    let file = dir.appendingPathComponent("awg.conf")
                    try awg.conf.write(to: file, atomically: true, encoding: .utf8)
                    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
                    try Helper.run(["start-awg", file.path, awg.address, String(awg.mtu), dns, ip, String(profile.int("awg.port"))])
                }
            }
            state = .up
            killSwitch = .active
            since = Date()
        } catch {
            self.error = error.localizedDescription
            state = .down
            activeProtocol = nil
        }
        changingConnection = false
        await refresh()
    }

    func disconnect() async {
        guard !changingConnection, !installingHelper else { return }
        changingConnection = true
        error = nil
        do {
            _ = try await background { try Helper.run(["stop"]) }
            state = .down
            killSwitch = .inactive
            activeProtocol = nil
            since = nil
        } catch {
            self.error = error.localizedDescription
        }
        changingConnection = false
        await refresh()
    }

    func addResult(_ r: SpeedResult) {
        var tagged = r
        tagged.serverId = selectedServerId
        results.insert(tagged, at: 0)
        store.saveResults(results)
    }

    func clearResults() {
        results = []
        store.saveResults([])
    }

    private func background<T>(_ work: @escaping () throws -> T) async throws -> T {
        try await Task.detached(priority: .userInitiated) { try work() }.value
    }

    private func background<T>(_ work: @escaping () -> T) async -> T {
        await Task.detached(priority: .userInitiated) { work() }.value
    }
}
