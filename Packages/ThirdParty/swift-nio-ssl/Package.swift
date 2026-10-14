// swift-tools-version:6.0
//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2021 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import PackageDescription

// Trimmed copy of swift-nio-ssl 2.37.5 (revision 322f3c2a4a21df31c84ca416bf65ee5e9059e440):
// only the NIOSSL library and its BoringSSL targets. See PATCH.md for the local changes.
//
// Warnings are suppressed as SwiftPM does for remote packages: this is third-party code.
//
// BoringSSL Commit: 817ab07ebb53da35afea409ab9328f578492832d

#if canImport(Darwin)
let includePrivacyManifest = true
#else
let includePrivacyManifest = false
#endif

let package = Package(
    name: "swift-nio-ssl",
    products: [
        .library(name: "NIOSSL", targets: ["NIOSSL"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.98.0")
    ],
    targets: [
        .target(
            name: "CNIOBoringSSL",
            cSettings: [
                .define("_GNU_SOURCE"),
                .define("_POSIX_C_SOURCE", to: "200112L"),
                .define("_DARWIN_C_SOURCE"),
                .unsafeFlags(["-w"]),
                .define("_WINSOCKAPI_", .when(platforms: [.windows])),
                .define("NOMINMAX", .when(platforms: [.windows])),
                .define("NOCRYPT", .when(platforms: [.windows])),
            ],
            cxxSettings: [
                .unsafeFlags(["-w"]),
                .define("_WINSOCKAPI_", .when(platforms: [.windows])),
                .define("NOMINMAX", .when(platforms: [.windows])),
                .define("NOCRYPT", .when(platforms: [.windows])),
            ]
        ),
        .target(
            name: "CNIOBoringSSLShims",
            dependencies: [
                "CNIOBoringSSL"
            ],
            cSettings: [
                .define("_GNU_SOURCE")
            ]
        ),
        .target(
            name: "NIOSSL",
            dependencies: [
                "CNIOBoringSSL",
                "CNIOBoringSSLShims",
                .product(name: "NIO", package: "swift-nio"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOConcurrencyHelpers", package: "swift-nio"),
                .product(name: "NIOTLS", package: "swift-nio"),
            ],
            exclude: includePrivacyManifest ? [] : ["PrivacyInfo.xcprivacy"],
            resources: includePrivacyManifest ? [.copy("PrivacyInfo.xcprivacy")] : [],
            swiftSettings: [.enableUpcomingFeature("MemberImportVisibility"), .unsafeFlags(["-suppress-warnings"])]
        ),
    ],
    cxxLanguageStandard: .cxx17
)
