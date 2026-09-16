// swift-tools-version: 5.9
// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
//
// The Swift package seen from the root of the repository, so that a Package.swift elsewhere can say
//   .package(url: "https://github.com/zoobc/tools.git", from: "0.1.0")
// It is the package of swift/Package.swift with explicit paths; development, tests and CI run in swift/.
import PackageDescription

let package = Package(
    name: "zbc",
    platforms: [.macOS(.v12), .iOS(.v15)],
    products: [
        .library(name: "ZBC", targets: ["ZBC"]),
        .executable(name: "zbc-cli", targets: ["zbc-cli"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .target(name: "ZBC", dependencies: [.product(name: "Crypto", package: "swift-crypto")], path: "swift/Sources/ZBC"),
        .executableTarget(name: "zbc-cli", dependencies: ["ZBC"], path: "swift/Sources/zbc-cli"),
        .testTarget(name: "ZBCTests", dependencies: ["ZBC"], path: "swift/Tests/ZBCTests"),
    ]
)
