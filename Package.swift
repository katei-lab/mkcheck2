// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
  name: "mkcheck2",
  dependencies: [
    .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.3.0"),
    .package(url: "https://github.com/apple/swift-log", from: "1.5.4"),
    .package(url: "https://github.com/apple/swift-testing", from: "0.7.0"),
    .package(url: "https://github.com/apple/swift-system", branch: "refs/pull/181/head"),
  ],
  targets: [
    .executableTarget(
      name: "mkcheck2",
      dependencies: [
        "mkcheck2abi",
        "mkcheck2syslinux",
        "mkcheck2bpf_skelton",
        .product(name: "ArgumentParser", package: "swift-argument-parser"),
        .product(name: "Logging", package: "swift-log"),
        .product(name: "SystemPackage", package: "swift-system"),
      ],
      exclude: ["CMakeLists.txt"]
    ),
    .target(
      name: "mkcheck2bpf_skelton",
      dependencies: [],
      path: "build/Sources/mkcheck2bpf",
      exclude: [],
      linkerSettings: [.linkedLibrary("bpf")]
    ),
    .target(
      name: "mkcheck2abi",
      dependencies: []
    ),
    .testTarget(
      name: "MkCheck2Tests",
      dependencies: [
        .product(name: "Testing", package: "swift-testing")
      ]),
    .executableTarget(
      name: "mkcheck2-test-utils",
      dependencies: [
        "mkcheck2syslinux",
        .product(name: "ArgumentParser", package: "swift-argument-parser"),
        .product(name: "SystemPackage", package: "swift-system"),
      ]
    ),
    .target(name: "mkcheck2syslinux", dependencies: []),
  ]
)
