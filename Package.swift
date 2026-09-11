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
        .testTarget(name: "AppAIGatewayTests", dependencies: ["AppAIGateway"]),
    ]
)
