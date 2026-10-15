import Foundation
import SwiftUI

enum VPNState { case down, connecting, up }

@MainActor
final class VPNManager: ObservableObject {
    let store = Store()

    @Published var state: VPNState = .down
    @Published var activeProtocol: VPNConnection?
    @Published var activeServerHost: String?
    @Published var selected: VPNConnection
    @Published var since: Date?
    @Published var error: String?
    @Published var helperReady = false
    @Published var results: [SpeedResult]
    @Published var updatingConfiguration = false
    @Published var configurationMessage: String?
    private let updateBootstrap = UpdateBootstrap.bundled

    var connections: [VPNConnection] { store.profile.connections }
    var canUpdateConfiguration: Bool { updateBootstrap != nil }

    func reloadProfileChoices() {
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
        selected = store.selectedConnection
        results = store.results()
        Task { await refresh() }
    }

    /// Синхронизация с реальным состоянием (VPN мог остаться поднятым с прошлого запуска).
    func refresh() async {
        helperReady = await background { Helper.isReady }
        guard helperReady else { return }
        let status = (try? await background { try Helper.run(["status"]) }) ?? "down"
        if status.hasPrefix("xray") || status.hasPrefix("awg") {
            if state != .up { state = .up; since = since ?? Date() }
            if activeProtocol == nil { activeProtocol = selected }
        } else if state == .up {
            state = .down
            activeProtocol = nil
        }
    }

    func installHelper() async {
        error = nil
        do {
            try await background { try Helper.install() }
        } catch {
            self.error = error.localizedDescription
        }
        await refresh()
    }

    func select(_ proto: VPNConnection) {
        guard state != .connecting, proto != selected else { return }
        selected = proto
        store.selectedConnection = proto
        if state != .down { Task { await connect() } }
    }

    func toggle() {
        Task { state == .down ? await connect() : await disconnect() }
    }

    func connect() async {
        guard state != .connecting else { return }
        let profile = store.profile
        let proto = profile.connections.first { $0.id == selected.id } ?? VPNConnection(.vlessTcp)
        selected = proto
        store.selectedConnection = proto
        error = nil
        state = .connecting
        activeProtocol = proto
        activeServerHost = profile.host
        do {
            let dir = runDir
            try await background {
                let dns = profile.dnsServers.joined(separator: ",")
                if proto.usesXray {
                    let file = dir.appendingPathComponent("xray.json")
                    try Configs.xray(profile, proto).write(to: file, atomically: true, encoding: .utf8)
                    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
                    try Helper.run(["start-xray", file.path, dns])
                } else {
                    let ip = try Configs.resolveIPv4(profile.host)
                    let awg = Configs.amnezia(profile, endpointIP: ip)
                    let file = dir.appendingPathComponent("awg.conf")
                    try awg.conf.write(to: file, atomically: true, encoding: .utf8)
                    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
                    try Helper.run(["start-awg", file.path, awg.address, String(awg.mtu), dns, ip])
                }
            }
            state = .up
            since = Date()
        } catch {
            self.error = error.localizedDescription
            state = .down
            activeProtocol = nil
        }
    }

    func disconnect() async {
        _ = try? await background { try Helper.run(["stop"]) }
        state = .down
        activeProtocol = nil
        since = nil
    }

    /// Синхронная остановка при выходе из приложения, чтобы не оставить чужие DNS и маршруты.
    nonisolated func stopSync() {
        _ = try? Helper.run(["stop"])
    }

    func addResult(_ r: SpeedResult) {
        results.insert(r, at: 0)
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
