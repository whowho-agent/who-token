// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "TokenKit",
    platforms: [
        .iOS(.v17),
        .macOS(.v14)
    ],
    products: [
        .library(name: "TokenKit", targets: ["TokenKit"]),
        .executable(name: "tokenctl", targets: ["tokenctl"])
    ],
    dependencies: [
        .package(url: "https://github.com/AktivCo/swift-rtpkcs11ecp-binary.git", exact: "2.22.1"),
        .package(url: "https://github.com/AktivCo/swift-rtpcsc-wrapper.git", exact: "1.9.0"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.0.0")
    ],
    targets: [
        // C shim exposing rtpkcs11ecp headers (the binary framework ships no module map).
        .target(
            name: "CPkcs11",
            dependencies: [.product(name: "rtpkcs11ecp", package: "swift-rtpkcs11ecp-binary")]
        ),
        .target(
            name: "TokenKit",
            dependencies: [
                "CPkcs11",
                .product(name: "X509", package: "swift-certificates"),
                // PC/SC (NFC session control) is only available on iOS; USB tokens work through PKCS#11 alone.
                .product(name: "RtPcscWrapper", package: "swift-rtpcsc-wrapper", condition: .when(platforms: [.iOS]))
            ]
        ),
        // macOS CLI for checking TokenKit against a real USB token without an iPhone.
        .executableTarget(
            name: "tokenctl",
            dependencies: ["TokenKit"]
        ),
        .testTarget(
            name: "TokenKitTests",
            dependencies: ["TokenKit"],
            resources: [.copy("Fixtures")]
        )
    ]
)
