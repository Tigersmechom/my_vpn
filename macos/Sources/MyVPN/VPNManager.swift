import Foundation
import SwiftUI

enum VPNState { case down, connecting, up }

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
    @Published var results: [SpeedResult]
    @Published var updatingConfiguration = false
    @Published var configurationMessage: String?
    @Published var availability: [String: AvailabilityResult] = [:]
    @Published var availabilityMessage: String?
    private var foreground = false
    private var stateKnown = false
    private var monitorTask: Task<Void, Never>?
    private var feedTask: Task<Void, Never>?
    private var healthProcess: AvailabilityProcess?
    private var monitorGeneration = 0
    private let updateBootstrap = UpdateBootstrap.bundled

    var connections: [VPNConnection] { store.selectedServer.profile.connections }
    var servers: [VPNServer] { store.profile.servers }
    var canUpdateConfiguration: Bool { updateBootstrap != nil }

    func reloadProfileChoices() {
        selectedServerId = store.selectedServer.id
        selected = store.selectedConnection
        results = store.results()
        availability = [:]
    }

    func updateConfiguration(manual: Bool = true) async {
        guard !updatingConfiguration, let bootstrap = updateBootstrap else { return }
        updatingConfiguration = true
        if manual { configurationMessage = "Проверяю обновления…" }
        defer { updatingConfiguration = false }
        do {
            let update = try await RemoteUpdates.fetch(bootstrap: bootstrap, highestRevision: store.highestRevision)
            try Task.checkCancellation()
            let changed = try store.applyRemote(update.profile, revision: update.revision, repair: manual)
            if changed {
                reloadProfileChoices()
                configurationMessage = "Конфигурация \(update.revision) сохранена. Новые маршруты появились в списке"
            } else if manual { configurationMessage = "У вас актуальная конфигурация (\(update.revision))" }
        } catch {
            if !Task.isCancelled { configurationMessage = error.localizedDescription }
        }
    }

    func setForeground(_ value: Bool) {
        foreground = value
        reconcileMonitoring()
    }

    private func stopMonitoring() {
        monitorGeneration += 1
        monitorTask?.cancel(); monitorTask = nil
        feedTask?.cancel(); feedTask = nil
        healthProcess?.stop(); healthProcess = nil
    }

    private func reconcileMonitoring() {
        guard foreground && stateKnown && state == .down else { stopMonitoring(); return }
        guard monitorTask == nil else { return }
        monitorGeneration += 1
        let generation = monitorGeneration
        let process = AvailabilityProcess()
        healthProcess = process
        availability = [:]
        availabilityMessage = nil
        monitorTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self, self.monitorGeneration == generation else { return }
                let start = Date()
                let catalog = self.store.selectedServer.profile
                let routes: [[String: Any]] = catalog.connections.compactMap { connection in
                    guard let proto = connection.builtin, proto != .vlessTcp else { return nil }
                    return ["id": connection.id, "protocol": proto.rawValue, "profile": catalog.connectionProfile(connection).json]
                }
                do {
                    let payload = try JSONSerialization.data(withJSONObject: ["routes": routes])
                    let values = try await process.check(payload)
                    guard !Task.isCancelled, self.monitorGeneration == generation, self.state == .down else { return }
                    guard catalog.serialized() == self.store.selectedServer.profile.serialized() else { continue }
                    self.availability = Dictionary(uniqueKeysWithValues: values.map { ($0.id, $0) })
                    self.availabilityMessage = nil
                } catch {
                    if !Task.isCancelled { self.availabilityMessage = "Проверка временно недоступна" }
                }
                do { try await Task.sleep(nanoseconds: UInt64(max(0.1, 5 - Date().timeIntervalSince(start)) * 1_000_000_000)) }
                catch { return }
            }
        }
        feedTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self, self.monitorGeneration == generation else { return }
                let start = Date()
                await self.updateConfiguration(manual: false)
                do { try await Task.sleep(nanoseconds: UInt64(max(0.1, 5 - Date().timeIntervalSince(start)) * 1_000_000_000)) }
                catch { return }
            }
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
        Task { await refresh() }
    }

    /// Синхронизация с реальным состоянием (VPN мог остаться поднятым с прошлого запуска).
    func refresh() async {
        helperReady = await background { Helper.isReady }
        if !helperReady { stateKnown = true; reconcileMonitoring(); return }
        guard let status = try? await background({ try Helper.run(["status"]) }) else {
            stateKnown = false
            stopMonitoring()
            return
        }
        if status.hasPrefix("xray") || status.hasPrefix("awg") {
            if state != .up { state = .up; since = since ?? Date() }
            if activeProtocol == nil { activeProtocol = selected }
        } else if state == .up {
            state = .down
            activeProtocol = nil
        }
        stateKnown = true
        reconcileMonitoring()
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

    func selectServer(_ id: String) {
        guard state == .down, let server = servers.first(where: { $0.id == id }) else { return }
        store.selectedServer = server
        reloadProfileChoices()
        stopMonitoring()
        reconcileMonitoring()
    }

    func toggle() {
        Task { state == .down ? await connect() : await disconnect() }
    }

    func connect() async {
        guard state != .connecting else { return }
        let catalog = store.selectedServer.profile
        let proto = catalog.connections.first { $0.id == selected.id } ?? catalog.connections[0]
        let profile = catalog.connectionProfile(proto)
        selected = proto
        store.selectedConnection = proto
        error = nil
        stopMonitoring()
        state = .connecting
        activeProtocol = proto
        activeServerHost = profile.host
        activeServerTitle = store.selectedServer.title
        do {
            let dir = runDir
            try await background {
                let dns = profile.dnsServers.joined(separator: ",")
                if proto.usesXray {
                    let file = dir.appendingPathComponent("xray.json")
                    try Configs.xray(catalog, proto).write(to: file, atomically: true, encoding: .utf8)
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
            reconcileMonitoring()
        }
    }

    func disconnect() async {
        _ = try? await background { try Helper.run(["stop"]) }
        state = .down
        activeProtocol = nil
        since = nil
        reconcileMonitoring()
    }

    /// Синхронная остановка при выходе из приложения, чтобы не оставить чужие DNS и маршруты.
    nonisolated func stopSync() {
        _ = try? Helper.run(["stop"])
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
