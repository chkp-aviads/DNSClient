// swift-tools-version:5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "DNSClient",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
    ],
    products: [
        // Products define the executables and libraries produced by a package, and make them visible to other packages.
        .library(
            name: "DNSClient",
            targets: [
                "DNSClient"
            ]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        .package(url: "https://github.com/chkp-aviads/swift-nio.git", from: "2.83.0"),
        .package(url: "https://github.com/chkp-aviads/swift-nio-transport-services.git", from: "1.24.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.5.3"),
        .package(url: "https://github.com/chkp-aviads/swift-nio-ssl.git", from: "2.31.0"),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages which this package depends on.
        .testTarget(
            name: "DNSClientTests",
            dependencies: [
                .target(name: "DNSClient"),
                .product(name: "NIO", package: "swift-nio"),
            ]),
        .target(
            name: "DNSClient",
            dependencies: [
                .product(name: "NIOTransportServices", package: "swift-nio-transport-services"),
                .product(name: "NIO", package: "swift-nio"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
            ]
        )
    ]
)
