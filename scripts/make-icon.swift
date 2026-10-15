import AppKit
import Foundation
let output = CommandLine.arguments[1]
try FileManager.default.createDirectory(atPath: output, withIntermediateDirectories: true)
for size in [16,32,64,128,256,512,1024] {
    let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size, bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)
    let ctx = NSGraphicsContext.current!.cgContext
    ctx.scaleBy(x: CGFloat(size)/1024, y: CGFloat(size)/1024)
    let rect = CGRect(x: 70, y: 70, width: 884, height: 884)
    NSColor(calibratedRed: 0.08, green: 0.10, blue: 0.13, alpha: 1).setFill()
    NSBezierPath(roundedRect: rect, xRadius: 195, yRadius: 195).fill()
    let mint = NSColor(calibratedRed: 0.46, green: 0.87, blue: 0.76, alpha: 1)
    mint.withAlphaComponent(0.12).setFill()
    NSBezierPath(ovalIn: CGRect(x: 224,y: 224,width: 576,height: 576)).fill()
    mint.setStroke()
    let ring = NSBezierPath(ovalIn: CGRect(x: 252,y: 252,width: 520,height: 520)); ring.lineWidth = 12; ring.stroke()
    for i in 0..<6 {
        let angle = Double(i) * .pi / 3
        let path = NSBezierPath(); path.lineWidth = 40; path.lineCapStyle = .round
        path.move(to: CGPoint(x: 512 + cos(angle)*45, y: 512 + sin(angle)*45))
        path.line(to: CGPoint(x: 512 + cos(angle)*175, y: 512 + sin(angle)*175)); path.stroke()
    }
    NSColor(calibratedRed: 0.96,green: 0.71,blue: 0.40,alpha: 1).setFill()
    NSBezierPath(ovalIn: CGRect(x: 718,y: 280,width: 48,height: 48)).fill()
    NSGraphicsContext.restoreGraphicsState()
    let data = bitmap.representation(using: .png, properties: [:])!
    let name = size == 1024 ? "icon_512x512@2x.png" : "icon_\(size)x\(size).png"
    if size != 64 { try data.write(to: URL(fileURLWithPath: output).appendingPathComponent(name)) }
    if size >= 32 && size <= 512 && size != 128 { try data.write(to: URL(fileURLWithPath: output).appendingPathComponent("icon_\(size/2)x\(size/2)@2x.png")) }
}
