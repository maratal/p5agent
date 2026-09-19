// swift-tools-version:5.9
// Hello World demo — Swift on SwiftNIO (+ NIOSSL for HTTPS).
import PackageDescription

let package = Package(
    name: "Hello",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.27.0"),
    ],
    targets: [
        // Named "App" so the swift type's default run command,
        // "App serve --env production" (the Vapor convention), starts it.
        .executableTarget(
            name: "App",
            dependencies: [
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
            ]
        ),
    ]
)
