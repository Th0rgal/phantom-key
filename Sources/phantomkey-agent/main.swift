import Foundation
import PhantomKeyCore
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

let args = CommandLine.arguments

let useSimulator = args.contains("--simulator")
let portArg = args.firstIndex(of: "--port").flatMap { idx in
    args.count > idx + 1 ? UInt16(args[idx + 1]) : nil
} ?? LoopbackSigningService.defaultPort

let sockPath: String
if let pathIdx = args.firstIndex(of: "--socket"), args.count > pathIdx + 1 {
    sockPath = args[pathIdx + 1]
} else if args.count > 1 && !args[1].hasPrefix("--") {
    sockPath = args[1]
} else {
    sockPath = "\(NSHomeDirectory())/.phantomkey/agent.sock"
}

// Ensure directory exists
let dir = (sockPath as NSString).deletingLastPathComponent
try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)

let agent = SSHAgent(socketPath: sockPath)
let semaphore = DispatchSemaphore(value: 0)

Task {
    let key: SSHAgentKey

    if useSimulator {
        // Connect to iOS simulator's signing service and register a credential
        fputs("Connecting to iOS simulator signing service on port \(portArg)...\n", stderr)

        do {
            let fd = try LoopbackSigningService.connect(port: portArg)
            fputs("Connected to iOS app!\n", stderr)

            // Register an SSH credential with the iOS authenticator
            let (credentialId, publicKey) = try LoopbackSigningService.makeCredential(
                fd: fd,
                rpId: "ssh:phantomkey",
                rpName: "PhantomKey SSH",
                userId: Data("phantomkey-ssh-user".utf8),
                userName: "thomas@phantomkey",
                userDisplayName: "Thomas"
            )

            fputs("Credential registered with iOS app (id: \(credentialId.prefix(8).map { String(format: "%02x", $0) }.joined())...)\n", stderr)

            // Create an SSH key that delegates signing to the iOS app
            key = SSHAgentKey(
                privateKey: publicKey,
                signingFD: fd,
                credentialId: credentialId,
                rpId: "ssh:phantomkey",
                comment: "thomas@phantomkey-ios"
            )
        } catch {
            fputs("Failed to connect to iOS simulator: \(error)\n", stderr)
            fputs("Make sure the iOS app is running in the simulator.\n", stderr)
            exit(1)
        }
    } else {
        // Local key generation (no iOS app involved)
        key = SSHAgentKey.generate(comment: "thomas@phantomkey")
    }

    await agent.addKey(key)
    do {
        try await agent.start()
    } catch {
        fputs("Failed to start agent: \(error)\n", stderr)
        exit(1)
    }

    let authLine = key.authorizedKeyLine
    print("SSH_AUTH_SOCK=\(sockPath); export SSH_AUTH_SOCK;")
    print("echo Agent pid \(ProcessInfo.processInfo.processIdentifier);")
    fputs("\n", stderr)
    if useSimulator {
        fputs("PhantomKey SSH Agent started (signing via iOS Simulator)\n", stderr)
    } else {
        fputs("PhantomKey SSH Agent started (local signing)\n", stderr)
    }
    fputs("Socket: \(sockPath)\n", stderr)
    fputs("Public key:\n\(authLine)\n\n", stderr)

    semaphore.signal()
}

semaphore.wait()
dispatchMain()
