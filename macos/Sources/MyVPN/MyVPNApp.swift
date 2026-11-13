import AppKit
import SwiftUI

@main
struct MyVPNApp: App {
    @StateObject private var vpn = VPNManager()

    var body: some Scene {
        Window("My VPN", id: "main") {
            ContentView()
                .environmentObject(vpn)
        }
        .windowResizability(.contentSize)

        Window("Рабочий стол США", id: "desktop-us") {
            RemoteDesktopView()
        }
        .defaultSize(width: 1200, height: 820)

        MenuBarExtra {
            MenuContent().environmentObject(vpn)
        } label: {
            Image(systemName: vpn.state == .up ? "shield.lefthalf.filled" : "shield.slash")
        }
    }
}

private struct MenuContent: View {
    @EnvironmentObject var vpn: VPNManager
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Text(vpn.state == .up ? "Туннель запущен · \(vpn.activeProtocol?.title ?? "")"
             : vpn.state == .connecting ? "Подключение…" : vpn.state == .blocked ? "Интернет заблокирован" : "Отключено")
        Button(vpn.state == .down || vpn.state == .blocked ? "Подключить" : "Отключить") { vpn.toggle() }
            .disabled(vpn.state == .connecting || !vpn.helperReady)
        if vpn.killSwitch == .blocked || vpn.killSwitch == .unavailable {
            Button("Отключить VPN и снять блокировку") { Task { await vpn.disconnect() } }
        }
        Divider()
        Picker("Сервер", selection: Binding(get: { vpn.selectedServerId }, set: { vpn.selectServer($0) })) {
            ForEach(vpn.servers) { Text($0.title).tag($0.id) }
        }
        .disabled(vpn.state == .up || vpn.state == .connecting)
        Picker("Протокол", selection: Binding(get: { vpn.selected }, set: { vpn.select($0) })) {
            ForEach(vpn.connections) { Text($0.title).tag($0) }
        }
        Divider()
        Button("Открыть окно") {
            openWindow(id: "main")
            NSApp.activate(ignoringOtherApps: true)
        }
        Button("Рабочий стол США") { openWindow(id: "desktop-us"); NSApp.activate(ignoringOtherApps: true) }
        if vpn.killSwitch == .active || vpn.killSwitch == .blocked {
            Text("При выходе VPN и защита остаются включены")
        }
        Button("Выход") { NSApp.terminate(nil) }.keyboardShortcut("q")
    }
}
