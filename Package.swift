// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "AppAIGateway",
    platforms: [.iOS(.v16), .macOS(.v13)],
    products: [
        .library(name: "AppAIGateway", targets: ["AppAIGateway"]),
    ],
    targets: [
        .target(
            name: "AppAIGateway",
            linkerSettings: [.linkedFramework("Security")]
        ),
        .testTarget(
            name: "AppAIGatewayTests",
            dependencies: ["AppAIGateway"],
            // Read by path, not bundled: the gateway's own tests read the same file.
            exclude: ["Fixtures"]
        ),
    ]
)
