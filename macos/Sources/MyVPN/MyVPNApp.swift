import AppKit
import SwiftUI

@main
struct MyVPNApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @StateObject private var vpn = VPNManager()

    var body: some Scene {
        Window("My VPN", id: "main") {
            ContentView()
                .environmentObject(vpn)
                .onAppear { appDelegate.vpn = vpn }
        }
        .windowResizability(.contentSize)

        MenuBarExtra {
            MenuContent().environmentObject(vpn)
        } label: {
            Image(systemName: vpn.state == .up ? "shield.lefthalf.filled" : "shield.slash")
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    var vpn: VPNManager?

    func applicationWillTerminate(_ notification: Notification) {
        // Не оставляем систему с DNS и маршрутами туннеля после выхода
        vpn?.stopSync()
    }
}

private struct MenuContent: View {
    @EnvironmentObject var vpn: VPNManager
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Text(vpn.state == .up ? "Подключено · \(vpn.activeProtocol?.title ?? "")"
             : vpn.state == .connecting ? "Подключение…" : "Отключено")
        Button(vpn.state == .down ? "Подключить" : "Отключить") { vpn.toggle() }
            .disabled(vpn.state == .connecting || !vpn.helperReady)
        Divider()
        Picker("Протокол", selection: Binding(get: { vpn.selected }, set: { vpn.select($0) })) {
            ForEach(vpn.connections) { Text($0.title).tag($0) }
        }
        Divider()
        Button("Открыть окно") {
            openWindow(id: "main")
            NSApp.activate(ignoringOtherApps: true)
        }
        Button("Выход") { NSApp.terminate(nil) }.keyboardShortcut("q")
    }
}
