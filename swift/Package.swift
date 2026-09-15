// swift-tools-version: 5.9
// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
import PackageDescription

let package = Package(
    name: "zbc",
    platforms: [.macOS(.v12), .iOS(.v15)],
    products: [
        .library(name: "ZBC", targets: ["ZBC"]),
        .executable(name: "zbc-cli", targets: ["zbc-cli"]),
    ],
    dependencies: [
        // CryptoKit on Apple platforms, BoringSSL elsewhere: Ed25519, SHA-512, HMAC.
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .target(name: "ZBC", dependencies: [.product(name: "Crypto", package: "swift-crypto")]),
        .executableTarget(name: "zbc-cli", dependencies: ["ZBC"]),
        // Writes Sources/ZBC/CommandsGen.swift from ../spec/transactions. `swift run gen`.
        .executableTarget(name: "gen"),
        .testTarget(name: "ZBCTests", dependencies: ["ZBC"]),
    ]
)
