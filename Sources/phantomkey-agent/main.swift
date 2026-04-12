import Foundation
import PhantomKeyCore

let sockPath: String
if CommandLine.arguments.count > 1 {
    sockPath = CommandLine.arguments[1]
} else {
    sockPath = "\(NSHomeDirectory())/.phantomkey/agent.sock"
}

// Ensure directory exists
let dir = (sockPath as NSString).deletingLastPathComponent
try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)

let agent = SSHAgent(socketPath: sockPath)
let key = SSHAgentKey.generate(comment: "thomas@phantomkey")

let semaphore = DispatchSemaphore(value: 0)

Task {
    await agent.addKey(key)
    do {
        try await agent.start()
    } catch {
        fputs("Failed to start agent: \(error)\n", stderr)
        exit(1)
    }

    let authLine = key.authorizedKeyLine
    // Print in a machine-parseable format
    print("SSH_AUTH_SOCK=\(sockPath); export SSH_AUTH_SOCK;")
    print("echo Agent pid \(ProcessInfo.processInfo.processIdentifier);")
    fputs("\n", stderr)
    fputs("PhantomKey SSH Agent started\n", stderr)
    fputs("Socket: \(sockPath)\n", stderr)
    fputs("Public key:\n\(authLine)\n\n", stderr)
    fputs("Usage:\n", stderr)
    fputs("  eval $(phantomkey-agent)\n", stderr)
    fputs("  ssh-add -L\n", stderr)
    fputs("  ssh user@host\n\n", stderr)

    semaphore.signal()
}

semaphore.wait()

// Keep running until killed
dispatchMain()
