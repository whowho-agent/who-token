// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "ProxyKit",
    platforms: [
        .iOS(.v17),
        .macOS(.v14)
    ],
    products: [
        .library(name: "ProxyKit", targets: ["ProxyKit"]),
        .executable(name: "standserver", targets: ["standserver"]),
        .executable(name: "mtlsctl", targets: ["mtlsctl"])
    ],
    dependencies: [
        .package(path: "../TokenKit"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
        // Local copy of 2.37.5 with client TLS session resumption, see ../ThirdParty/swift-nio-ssl/PATCH.md.
        .package(path: "../ThirdParty/swift-nio-ssl"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.0.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"5.0.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.0.0")
    ],
    targets: [
        .target(
            name: "ProxyKit",
            dependencies: [
                "TokenKit",
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOTLS", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "SwiftASN1", package: "swift-asn1")
            ]
        ),
        // Test stand for the browser: HTTPS with keep-alive that requires a client certificate.
        .executableTarget(
            name: "standserver",
            dependencies: [
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOHTTP1", package: "swift-nio"),
                .product(name: "NIOTLS", package: "swift-nio"),
                .product(name: "NIOSSL", package: "swift-nio-ssl")
            ]
        ),
        // macOS CLI: GET over mTLS with the key on a USB Rutoken.
        .executableTarget(
            name: "mtlsctl",
            dependencies: ["ProxyKit", "TokenKit"]
        ),
        .testTarget(
            name: "ProxyKitTests",
            dependencies: [
                "ProxyKit",
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "NIOPosix", package: "swift-nio")
            ],
            resources: [.copy("Fixtures")]
        )
    ]
)
