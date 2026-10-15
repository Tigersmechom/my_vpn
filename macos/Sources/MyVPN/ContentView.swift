import AppKit
import SwiftUI

struct ContentView: View {
    @EnvironmentObject var vpn: VPNManager
    @State private var showSettings = false
    @State private var testing = false
    @State private var testStep = ""
    @State private var testError: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                if !vpn.helperReady { helperBanner }
                statusCard
                section("Протокол")
                VStack(spacing: 6) {
                    ForEach(vpn.connections) { p in protocolRow(p) }
                }
                updateCard
                section("Тест скорости")
                speedCard
                if !vpn.results.isEmpty {
                    section("Сравнение (среднее по последним 3 замерам)")
                    comparison
                    HStack {
                        section("История")
                        Spacer()
                        Button("Очистить") { vpn.clearResults() }.buttonStyle(.link)
                    }
                    history
                }
            }
            .padding(20)
        }
        .frame(width: 520, height: 820)
        .toolbar {
            Button { showSettings = true } label: { Label("Настройки сервера", systemImage: "gearshape") }
        }
        .sheet(isPresented: $showSettings, onDismiss: { vpn.reloadProfileChoices() }) { SettingsView(store: vpn.store) }
    }

    private var helperBanner: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Нужен служебный компонент").font(.headline)
            Text("Чтобы управлять сетью (TUN, маршруты, DNS), приложение один раз установит helper. macOS попросит пароль администратора.")
                .font(.callout).foregroundStyle(.secondary)
            Button("Установить") { Task { await vpn.installHelper() } }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.orange.opacity(0.15), in: RoundedRectangle(cornerRadius: 12))
    }

    private var statusColor: Color {
        switch vpn.state {
        case .up: return .green
        case .connecting: return .orange
        case .down: return .secondary
        }
    }

    private var statusCard: some View {
        VStack(spacing: 12) {
            Button(action: vpn.toggle) {
                ZStack {
                    Circle().fill(statusColor.opacity(0.15))
                    Circle().stroke(statusColor, lineWidth: 6)
                    if vpn.state == .connecting {
                        ProgressView()
                    } else {
                        Text(vpn.state == .up ? "ОТКЛ." : "ВКЛ.")
                            .font(.system(size: 22, weight: .bold)).foregroundStyle(statusColor)
                    }
                }
                .frame(width: 130, height: 130)
            }
            .buttonStyle(.plain)
            .disabled(vpn.state == .connecting || !vpn.helperReady)

            Text(vpn.state == .up ? "Подключено" : vpn.state == .connecting ? "Подключение…" : "Отключено")
                .font(.title2.weight(.semibold))
            TimelineView(.periodic(from: .now, by: 1)) { ctx in
                Text(details(now: ctx.date)).font(.callout)
            }
            Text("Сервер \(vpn.state == .down ? vpn.store.profile.host : (vpn.activeServerHost ?? vpn.store.profile.host))")
                .font(.caption).foregroundStyle(.secondary)
            if let e = vpn.error {
                Text(e).font(.caption).foregroundStyle(.red).multilineTextAlignment(.center).textSelection(.enabled)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 20)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 14))
    }

    private func details(now: Date) -> String {
        var parts: [String] = []
        if vpn.state != .down, let p = vpn.activeProtocol { parts.append(p.title) }
        if vpn.state == .up, let since = vpn.since {
            let s = max(0, Int(now.timeIntervalSince(since)))
            parts.append(String(format: "%02d:%02d:%02d", s / 3600, s / 60 % 60, s % 60))
        }
        return parts.joined(separator: " · ")
    }

    private func protocolRow(_ p: VPNConnection) -> some View {
        let selected = vpn.selected == p
        return Button { vpn.select(p) } label: {
            HStack(spacing: 10) {
                Image(systemName: selected ? "largecircle.fill.circle" : "circle")
                    .foregroundStyle(selected ? Color.accentColor : .secondary)
                VStack(alignment: .leading, spacing: 2) {
                    Text(p.title).fontWeight(.medium)
                    Text(p.subtitle).font(.caption).foregroundStyle(.secondary)
                }
                Spacer()
            }
            .padding(10)
            .contentShape(Rectangle())
            .background(selected ? Color.accentColor.opacity(0.12) : Color.secondary.opacity(0.06),
                        in: RoundedRectangle(cornerRadius: 10))
        }
        .buttonStyle(.plain)
    }

    private var updateCard: some View {
        VStack(alignment: .leading, spacing: 6) {
            Button {
                Task { await vpn.updateConfiguration() }
            } label: {
                HStack {
                    if vpn.updatingConfiguration { ProgressView().controlSize(.small) }
                    Text("Обновить конфигурацию")
                }
            }
            .disabled(!vpn.canUpdateConfiguration || vpn.updatingConfiguration)
            Text(vpn.configurationMessage ?? (vpn.canUpdateConfiguration
                 ? "Новые параметры сервера и совместимые режимы применятся при следующем подключении"
                 : "Канал обновлений не настроен в этой сборке"))
                .font(.caption).foregroundStyle(.secondary)
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.secondary.opacity(0.06), in: RoundedRectangle(cornerRadius: 10))
    }

    private var speedCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            if testing {
                HStack { ProgressView().controlSize(.small); Text(testStep) }
            } else if let last = vpn.results.first {
                Text(last.label).font(.subheadline.weight(.medium))
                HStack {
                    metric("Пинг", "\(last.pingMs) мс")
                    Spacer()
                    metric("Загрузка", String(format: "%.1f Мбит/с", last.downMbps))
                    Spacer()
                    metric("Отдача", String(format: "%.1f Мбит/с", last.upMbps))
                }
                Text("Внешний IP: \(last.exitIp)").font(.caption).foregroundStyle(.secondary)
            } else {
                Text("Подключитесь и запустите тест, чтобы сравнить протоколы.").foregroundStyle(.secondary)
            }
            if let e = testError { Text(e).font(.caption).foregroundStyle(.red) }
            Button {
                guard let proto = vpn.activeProtocol else { return }
                testing = true
                testError = nil
                Task {
                    do {
                        let r = try await SpeedTest.run(proto) { testStep = $0 }
                        vpn.addResult(r)
                    } catch {
                        testError = "Тест не удался: \(error.localizedDescription)"
                    }
                    testing = false
                }
            } label: { Text("Запустить тест").frame(maxWidth: .infinity) }
            .controlSize(.large)
            .disabled(vpn.state != .up || testing)
        }
        .padding(14)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 12))
    }

    private var comparison: some View {
        Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 6) {
            GridRow {
                Text("Протокол"); Text("Пинг"); Text("↓ Мбит/с"); Text("↑ Мбит/с")
            }
            .font(.caption.weight(.semibold))
            Divider()
            ForEach(vpn.connections) { proto in
                let last = vpn.results.filter { $0.protocolRaw == proto.id }.prefix(3)
                GridRow {
                    Text(proto.title)
                    if last.isEmpty {
                        Text("—"); Text("—"); Text("—")
                    } else {
                        Text("\(last.map(\.pingMs).reduce(0, +) / last.count) мс")
                        Text(String(format: "%.1f", last.map(\.downMbps).reduce(0, +) / Double(last.count)))
                        Text(String(format: "%.1f", last.map(\.upMbps).reduce(0, +) / Double(last.count)))
                    }
                }
                .font(.callout.monospacedDigit())
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 12))
    }

    private var history: some View {
        VStack(alignment: .leading, spacing: 4) {
            ForEach(vpn.results) { r in
                HStack {
                    Text(Date(timeIntervalSince1970: r.time), format: .dateTime.day().month().hour().minute())
                        .frame(width: 110, alignment: .leading)
                    Text(r.label)
                    Spacer()
                    Text(String(format: "%d мс · ↓%.0f · ↑%.0f", r.pingMs, r.downMbps, r.upMbps))
                }
                .font(.caption.monospacedDigit())
            }
        }
    }

    private func metric(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading) {
            Text(label).font(.caption).foregroundStyle(.secondary)
            Text(value).font(.headline)
        }
    }

    private func section(_ title: String) -> some View {
        Text(title).font(.subheadline.weight(.semibold)).foregroundStyle(Color.accentColor)
    }
}

struct SettingsView: View {
    let store: Store
    @Environment(\.dismiss) private var dismiss
    @State private var values: [String: String] = [:]
    @State private var message: String?
    @State private var confirmReset = false
    @State private var importedProfile: Profile?

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Настройки сервера").font(.headline)
                Spacer()
                Button("Из буфера") { pasteProfile() }
                Button("Сбросить") { confirmReset = true }
            }
            .padding()
            Divider()
            Form {
                Text("Данные сервера уже вписаны. Изменения применяются при следующем подключении.")
                    .font(.caption).foregroundStyle(.secondary)
                ForEach(Fields.groups) { group in
                    Section(group.title) {
                        ForEach(group.fields) { f in
                            TextField(f.label, text: Binding(get: { values[f.path] ?? "" }, set: { values[f.path] = $0 }))
                                .font(.system(.body, design: .monospaced))
                        }
                    }
                }
            }
            .formStyle(.grouped)
            Divider()
            HStack {
                if let message { Text(message).font(.caption).foregroundStyle(.secondary) }
                Spacer()
                Button("Отмена") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Сохранить") {
                    store.profile = (importedProfile ?? store.profile).with(values)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
            }
            .padding()
        }
        .frame(width: 560, height: 680)
        .onAppear { values = Self.values(of: store.profile) }
        .confirmationDialog("Сбросить настройки?", isPresented: $confirmReset) {
            Button("Сбросить", role: .destructive) {
                store.resetProfile()
                importedProfile = nil
                values = Self.values(of: store.resetTarget)
                message = "Восстановлена последняя загруженная конфигурация"
            }
        } message: {
            Text("Вернутся последние загруженные данные сервера, либо исходные данные приложения.")
        }
    }

    private func pasteProfile() {
        let text = NSPasteboard.general.string(forType: .string) ?? ""
        if let p = try? Profile.parse(text) {
            importedProfile = p
            values = Self.values(of: p)
            message = "Профиль вставлен — не забудьте сохранить"
        } else {
            message = "В буфере нет профиля (JSON из `vpnctl profile`)"
        }
    }

    private static func values(of p: Profile) -> [String: String] {
        Dictionary(uniqueKeysWithValues: Fields.byPath.keys.map { ($0, p.str($0)) })
    }
}
