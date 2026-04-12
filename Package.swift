// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "PhantomKey",
    platforms: [
        .macOS(.v14),
        .iOS(.v17),
    ],
    products: [
        .library(name: "PhantomKeyCore", targets: ["PhantomKeyCore"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .target(
            name: "PhantomKeyCore",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            path: "Sources/PhantomKeyCore"
        ),
        .testTarget(
            name: "PhantomKeyCoreTests",
            dependencies: ["PhantomKeyCore"],
            path: "Tests/PhantomKeyCoreTests"
        ),
    ]
)
