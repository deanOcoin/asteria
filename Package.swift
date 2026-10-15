// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "Asteria", platforms: [.macOS(.v14)], products: [.executable(name: "Asteria", targets: ["Asteria"])], targets: [.executableTarget(name: "Asteria", path: "Sources/Asteria")])
