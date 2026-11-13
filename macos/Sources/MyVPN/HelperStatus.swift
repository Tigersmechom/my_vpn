import Foundation

enum VPNState { case down, connecting, up, blocked }
enum KillSwitchState { case inactive, active, blocked, unavailable }

/// Helper is authoritative, including after application/core crashes and restarts.
struct HelperStatus {
    let state: VPNState
    let protection: KillSwitchState

    init(_ text: String) throws {
        let lines = text.split(separator: "\n").map(String.init)
        let running = lines.first?.hasPrefix("xray ") == true || lines.first?.hasPrefix("awg ") == true
        guard running || lines.first == "down" || lines.first == "blocked",
              lines.filter({ $0.hasPrefix("kill-switch ") }).count <= 1,
              lines.first != "blocked" || lines.contains("kill-switch on") else {
            throw VPNError("Некорректный ответ сетевого компонента")
        }
        if lines.contains("kill-switch on") {
            state = running ? .up : .blocked
            protection = running ? .active : .blocked
        } else {
            state = running ? .up : .down
            protection = lines.contains("kill-switch failed") || running ? .unavailable : .inactive
        }
    }
}
