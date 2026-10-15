// Рисует иконку приложения (щит с галочкой) в набор PNG для iconutil.
//   swift make-icon.swift <папка .iconset>
import AppKit

let out = URL(fileURLWithPath: CommandLine.arguments[1])
try? FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)

func render(_ px: Int) -> Data {
    let s = CGFloat(px)
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8,
                               samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                               colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)

    // фон — скруглённый квадрат в стиле macOS
    let inset = s * 0.09
    let bg = NSBezierPath(roundedRect: NSRect(x: inset, y: inset, width: s - 2 * inset, height: s - 2 * inset),
                          xRadius: s * 0.2, yRadius: s * 0.2)
    NSGradient(starting: NSColor(red: 0.09, green: 0.40, blue: 0.20, alpha: 1),
               ending: NSColor(red: 0.05, green: 0.22, blue: 0.12, alpha: 1))!.draw(in: bg, angle: -90)

    // щит
    let shield = NSBezierPath()
    shield.move(to: NSPoint(x: s * 0.5, y: s * 0.78))
    shield.line(to: NSPoint(x: s * 0.72, y: s * 0.70))
    shield.line(to: NSPoint(x: s * 0.72, y: s * 0.50))
    shield.curve(to: NSPoint(x: s * 0.5, y: s * 0.22), controlPoint1: NSPoint(x: s * 0.72, y: s * 0.36),
                 controlPoint2: NSPoint(x: s * 0.62, y: s * 0.27))
    shield.curve(to: NSPoint(x: s * 0.28, y: s * 0.50), controlPoint1: NSPoint(x: s * 0.38, y: s * 0.27),
                 controlPoint2: NSPoint(x: s * 0.28, y: s * 0.36))
    shield.line(to: NSPoint(x: s * 0.28, y: s * 0.70))
    shield.close()
    NSColor(red: 0.29, green: 0.87, blue: 0.50, alpha: 1).setFill()
    shield.fill()

    // галочка
    let check = NSBezierPath()
    check.move(to: NSPoint(x: s * 0.40, y: s * 0.50))
    check.line(to: NSPoint(x: s * 0.47, y: s * 0.43))
    check.line(to: NSPoint(x: s * 0.61, y: s * 0.58))
    check.lineWidth = s * 0.05
    check.lineCapStyle = .round
    check.lineJoinStyle = .round
    NSColor(red: 0.05, green: 0.22, blue: 0.12, alpha: 1).setStroke()
    check.stroke()

    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

for size in [16, 32, 128, 256, 512] {
    try render(size).write(to: out.appendingPathComponent("icon_\(size)x\(size).png"))
    try render(size * 2).write(to: out.appendingPathComponent("icon_\(size)x\(size)@2x.png"))
}
