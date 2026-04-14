import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

// MARK: - SSH Agent Protocol Constants

private enum SSHAgentMessage: UInt8 {
    case failure = 5
    case success = 6
    case requestIdentities = 11
    case identitiesAnswer = 12
    case signRequest = 13
    case signResponse = 14
    case addIdentity = 17
    case removeIdentity = 18
    case removeAllIdentities = 19
    case lock = 22
    case unlock = 23
    case extensionRequest = 27
}

// MARK: - SSH Wire Format Helpers

/// Builds SSH wire-format messages (length-prefixed strings, uint32, etc.)
struct SSHWireFormat {
    /// Encode a string (4-byte big-endian length + bytes)
    static func encodeString(_ data: Data) -> Data {
        var result = Data()
        var len = UInt32(data.count).bigEndian
        result.append(Data(bytes: &len, count: 4))
        result.append(data)
        return result
    }

    static func encodeString(_ str: String) -> Data {
        encodeString(Data(str.utf8))
    }

    /// Encode a uint32 in big-endian
    static func encodeUInt32(_ value: UInt32) -> Data {
        var be = value.bigEndian
        return Data(bytes: &be, count: 4)
    }

    /// Decode a string (4-byte length + bytes) from data at offset, advancing offset
    static func decodeString(_ data: Data, offset: inout Int) -> Data? {
        guard offset + 4 <= data.count else { return nil }
        let lb0 = UInt32(data[offset]) << 24
        let lb1 = UInt32(data[offset+1]) << 16
        let lb2 = UInt32(data[offset+2]) << 8
        let lb3 = UInt32(data[offset+3])
        let len = Int(lb0 | lb1 | lb2 | lb3)
        offset += 4
        guard offset + len <= data.count else { return nil }
        let result = Data(data[offset..<(offset + len)])
        offset += len
        return result
    }

    /// Decode a uint32 from data at offset, advancing offset
    static func decodeUInt32(_ data: Data, offset: inout Int) -> UInt32? {
        guard offset + 4 <= data.count else { return nil }
        let vb0 = UInt32(data[offset]) << 24
        let vb1 = UInt32(data[offset+1]) << 16
        let vb2 = UInt32(data[offset+2]) << 8
        let vb3 = UInt32(data[offset+3])
        let val = vb0 | vb1 | vb2 | vb3
        offset += 4
        return val
    }

    /// Build the SSH public key blob for an ECDSA P-256 key.
    /// Format: string("ecdsa-sha2-nistp256") + string("nistp256") + string(0x04 || x || y)
    static func ecdsaPublicKeyBlob(publicKey: P256.Signing.PublicKey) -> Data {
        var blob = Data()
        blob.append(encodeString("ecdsa-sha2-nistp256"))
        blob.append(encodeString("nistp256"))
        // Uncompressed EC point: 0x04 || x || y
        var point = Data([0x04])
        point.append(publicKey.rawRepresentation) // rawRepresentation is x || y (64 bytes)
        blob.append(encodeString(point))
        return blob
    }

    /// Build the SSH signature blob for ECDSA P-256.
    /// Format: string("ecdsa-sha2-nistp256") + string(DER-encoded r,s as SSH mpint pair)
    static func ecdsaSignatureBlob(signature: P256.Signing.ECDSASignature) -> Data {
        var blob = Data()
        blob.append(encodeString("ecdsa-sha2-nistp256"))
        // SSH encodes ECDSA sigs as: string(mpint(r) + mpint(s))
        let (r, s) = extractRS(from: signature.derRepresentation)
        var inner = Data()
        inner.append(encodeMPInt(r))
        inner.append(encodeMPInt(s))
        blob.append(encodeString(inner))
        return blob
    }

    /// Extract r and s from a DER-encoded ECDSA signature
    static func extractRS(from der: Data) -> (Data, Data) {
        // DER: 0x30 <len> 0x02 <rlen> <r> 0x02 <slen> <s>
        var offset = 0
        guard der.count > 6, der[0] == 0x30 else { return (Data(), Data()) }
        offset = 2 // skip SEQUENCE tag + length

        guard der[offset] == 0x02 else { return (Data(), Data()) }
        offset += 1
        let rLen = Int(der[offset])
        offset += 1
        let r = Data(der[offset..<(offset + rLen)])
        offset += rLen

        guard offset < der.count, der[offset] == 0x02 else { return (Data(), Data()) }
        offset += 1
        let sLen = Int(der[offset])
        offset += 1
        let s = Data(der[offset..<(offset + sLen)])

        return (r, s)
    }

    /// Encode a big integer as SSH mpint (strip leading zeros, add 0x00 if high bit set)
    static func encodeMPInt(_ data: Data) -> Data {
        var trimmed = data
        // Remove leading zeros (but keep at least one byte)
        while trimmed.count > 1 && trimmed[trimmed.startIndex] == 0 {
            trimmed = trimmed.dropFirst()
        }
        // Add leading zero if high bit is set (mpint is signed)
        if let first = trimmed.first, first & 0x80 != 0 {
            trimmed.insert(0x00, at: trimmed.startIndex)
        }
        return encodeString(trimmed)
    }
}

// MARK: - SSH Agent Key

/// An SSH agent key: an ECDSA P-256 key pair with a comment.
/// Supports two modes:
/// - Local: signs directly with a P256 private key
/// - Delegated: forwards sign requests to an iOS authenticator via loopback TCP
public struct SSHAgentKey: @unchecked Sendable {
    public let publicKey: P256.Signing.PublicKey
    public let comment: String

    // Local signing
    private let localPrivateKey: P256.Signing.PrivateKey?

    // Delegated signing (via iOS app)
    let signingFD: Int32?
    let credentialId: Data?
    let rpId: String?
    /// Serializes all delegated signing I/O on the shared TCP socket.
    private let signingLock: NSLock?

    /// Create a key for local signing.
    public init(privateKey: P256.Signing.PrivateKey, comment: String) {
        self.publicKey = privateKey.publicKey
        self.localPrivateKey = privateKey
        self.comment = comment
        self.signingFD = nil
        self.credentialId = nil
        self.rpId = nil
        self.signingLock = nil
    }

    /// Create a key for delegated signing via iOS authenticator.
    public init(publicKey: P256.Signing.PublicKey, signingFD: Int32, credentialId: Data, rpId: String, comment: String) {
        self.publicKey = publicKey
        self.localPrivateKey = nil
        self.comment = comment
        self.signingFD = signingFD
        self.credentialId = credentialId
        self.rpId = rpId
        self.signingLock = NSLock()
    }

    /// Generate a new SSH key with the given comment (local signing).
    public static func generate(comment: String) -> SSHAgentKey {
        SSHAgentKey(privateKey: P256.Signing.PrivateKey(), comment: comment)
    }

    /// The public key blob in SSH wire format.
    public var publicKeyBlob: Data {
        SSHWireFormat.ecdsaPublicKeyBlob(publicKey: publicKey)
    }

    /// The public key in OpenSSH authorized_keys format.
    public var authorizedKeyLine: String {
        "ecdsa-sha2-nistp256 \(publicKeyBlob.base64EncodedString()) \(comment)"
    }

    /// Sign data - either locally or by delegating to iOS.
    func sign(_ data: Data) throws -> P256.Signing.ECDSASignature {
        if let localPrivateKey {
            return try localPrivateKey.signature(for: data)
        }

        guard let fd = signingFD, let credId = credentialId, let lock = signingLock else {
            throw SSHAgentError.connectionFailed
        }

        // Serialize access to the shared TCP socket
        lock.lock()
        defer { lock.unlock() }

        // Send direct-sign request to iOS app
        let payload = CBOREncoder().encode(.map([
            (.unsignedInt(1), .byteString(credId)),
            (.unsignedInt(2), .byteString(data)),
        ]))
        let request = Envelope(type: .directSignRequest, sequence: 0, payload: payload)
        try LoopbackSigningService.sendMessage(fd, envelope: request)
        let response = try LoopbackSigningService.receiveMessage(fd)
        guard response.type == .directSignResponse else {
            throw SSHAgentError.connectionFailed
        }
        let decoded = try CBORDecoder().decode(response.payload)
        guard case .map(let pairs) = decoded,
              let sigEntry = pairs.first(where: { $0.0 == .unsignedInt(1) }),
              case .byteString(let sigDER) = sigEntry.1 else {
            throw SSHAgentError.connectionFailed
        }
        return try P256.Signing.ECDSASignature(derRepresentation: sigDER)
    }
}

// MARK: - SSH Agent

/// A minimal SSH agent that handles ECDSA P-256 keys.
/// Listens on a Unix domain socket and responds to SSH agent protocol requests.
public actor SSHAgent {
    private var keys: [SSHAgentKey] = []
    private let socketPath: String
    private var serverSocket: Int32 = -1
    private var isRunning = false
    private var acceptTask: Task<Void, Never>?

    public init(socketPath: String) {
        self.socketPath = socketPath
    }

    deinit {
        // Non-isolated cleanup of the socket file
        let path = socketPath
        let fd = serverSocket
        if fd >= 0 { close(fd) }
        unlink(path)
    }

    /// Add a key to the agent.
    public func addKey(_ key: SSHAgentKey) {
        keys.append(key)
    }

    /// Current snapshot of keys (for client handlers).
    var currentKeys: [SSHAgentKey] { keys }

    /// Remove all keys. Closes any delegated signing file descriptors.
    public func removeAllKeys() {
        for key in keys {
            if let fd = key.signingFD, fd >= 0 {
                close(fd)
            }
        }
        keys.removeAll()
    }

    /// Get the number of keys.
    public var keyCount: Int { keys.count }

    /// Start listening on the Unix socket.
    public func start() throws {
        guard !isRunning else { return }

        // Remove stale socket file
        unlink(socketPath)

        // Create Unix domain socket
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw SSHAgentError.socketCreationFailed }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = socketPath.utf8CString
        let maxLen = MemoryLayout.size(ofValue: addr.sun_path)
        withUnsafeMutableBytes(of: &addr.sun_path) { buf in
            for i in 0..<min(pathBytes.count, maxLen) {
                buf[i] = UInt8(bitPattern: pathBytes[i])
            }
        }

        let bindResult = withUnsafePointer(to: &addr) { addrPtr in
            addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                bind(fd, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bindResult == 0 else {
            Darwin.close(fd)
            throw SSHAgentError.bindFailed(errno)
        }

        // Set socket permissions to owner-only
        chmod(socketPath, 0o600)

        guard listen(fd, 5) == 0 else {
            Darwin.close(fd)
            throw SSHAgentError.listenFailed(errno)
        }

        serverSocket = fd
        isRunning = true

        // Start accepting connections
        acceptTask = Task { [weak self] in
            await self?.acceptLoop()
        }
    }

    /// Stop the agent. Closes the listening socket and all delegated signing FDs.
    public func stop() {
        isRunning = false
        acceptTask?.cancel()
        acceptTask = nil
        if serverSocket >= 0 {
            close(serverSocket)
            serverSocket = -1
        }
        for key in keys {
            if let fd = key.signingFD, fd >= 0 {
                close(fd)
            }
        }
        keys.removeAll()
        unlink(socketPath)
    }

    // MARK: - Accept Loop

    private func acceptLoop() async {
        let fd = serverSocket
        // Make the socket non-blocking so we can check cancellation
        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)

        while isRunning && !Task.isCancelled {
            var clientAddr = sockaddr_un()
            var addrLen = socklen_t(MemoryLayout<sockaddr_un>.size)
            let clientFD = withUnsafeMutablePointer(to: &clientAddr) { addrPtr in
                addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                    accept(fd, sockaddrPtr, &addrLen)
                }
            }

            if clientFD >= 0 {
                // Handle client on a GCD queue to keep blocking socket I/O off the
                // Swift cooperative thread pool.
                let agent = self
                DispatchQueue.global(qos: .userInitiated).async {
                    Self.handleClientBlocking(fd: clientFD, agent: agent)
                }
            } else if errno == EWOULDBLOCK || errno == EAGAIN {
                // No pending connections, sleep briefly
                try? await Task.sleep(nanoseconds: 50_000_000) // 50ms
            } else {
                break
            }
        }
    }

    // MARK: - Client Handling

    /// Synchronously bridge to an async actor call from a GCD queue.
    private static func syncAwait<T: Sendable>(_ op: @Sendable @escaping () async -> T) -> T {
        let sem = DispatchSemaphore(value: 0)
        let box = ResultBox<T>()
        Task {
            box.value = await op()
            sem.signal()
        }
        sem.wait()
        return box.value!
    }

    private static func syncAwait(_ op: @Sendable @escaping () async -> Void) {
        let sem = DispatchSemaphore(value: 0)
        Task {
            await op()
            sem.signal()
        }
        sem.wait()
    }

    /// Handle a client connection on a GCD thread. All socket I/O is blocking;
    /// actor calls are bridged via `syncAwait`.
    private static func handleClientBlocking(fd: Int32, agent: SSHAgent) {
        defer { close(fd) }

        // Ensure the client socket is blocking
        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags & ~O_NONBLOCK)

        while true {
            // Read 4-byte message length
            guard let lenData = readExact(fd: fd, count: 4) else { return }
            let b0 = UInt32(lenData[0]) << 24
            let b1 = UInt32(lenData[1]) << 16
            let b2 = UInt32(lenData[2]) << 8
            let b3 = UInt32(lenData[3])
            let msgLen = Int(b0 | b1 | b2 | b3)
            guard msgLen > 0, msgLen < 256 * 1024 else { return }

            // Read message body
            guard let msgData = readExact(fd: fd, count: msgLen) else { return }
            guard let msgType = SSHAgentMessage(rawValue: msgData[0]) else {
                sendMessage(fd: fd, data: Data([SSHAgentMessage.failure.rawValue]))
                continue
            }

            let payload = Data(msgData.dropFirst())
            let response: Data

            // Query fresh keys from the actor for each request
            let keys = syncAwait { await agent.currentKeys }

            switch msgType {
            case .requestIdentities:
                response = handleRequestIdentities(keys: keys)
            case .signRequest:
                response = handleSignRequest(payload: payload, keys: keys)
            case .removeAllIdentities:
                syncAwait { await agent.removeAllKeys() }
                response = Data([SSHAgentMessage.success.rawValue])
            case .lock, .unlock:
                response = Data([SSHAgentMessage.success.rawValue])
            default:
                response = Data([SSHAgentMessage.failure.rawValue])
            }

            sendMessage(fd: fd, data: response)
        }
    }

    private static func handleRequestIdentities(keys: [SSHAgentKey]) -> Data {
        var response = Data([SSHAgentMessage.identitiesAnswer.rawValue])
        response.append(SSHWireFormat.encodeUInt32(UInt32(keys.count)))
        for key in keys {
            response.append(SSHWireFormat.encodeString(key.publicKeyBlob))
            response.append(SSHWireFormat.encodeString(key.comment))
        }
        return response
    }

    private static func handleSignRequest(payload: Data, keys: [SSHAgentKey]) -> Data {
        var offset = 0
        guard let keyBlob = SSHWireFormat.decodeString(payload, offset: &offset),
              let dataToSign = SSHWireFormat.decodeString(payload, offset: &offset) else {
            return Data([SSHAgentMessage.failure.rawValue])
        }
        // flags are at offset but we ignore them for now
        // let flags = SSHWireFormat.decodeUInt32(payload, offset: &offset) ?? 0

        // Find matching key
        guard let key = keys.first(where: { $0.publicKeyBlob == keyBlob }) else {
            return Data([SSHAgentMessage.failure.rawValue])
        }

        // Sign the data (locally or via iOS delegated signing)
        guard let signature = try? key.sign(dataToSign) else {
            return Data([SSHAgentMessage.failure.rawValue])
        }

        let sigBlob = SSHWireFormat.ecdsaSignatureBlob(signature: signature)
        var response = Data([SSHAgentMessage.signResponse.rawValue])
        response.append(SSHWireFormat.encodeString(sigBlob))
        return response
    }

    // MARK: - Socket I/O

    private static func readExact(fd: Int32, count: Int) -> Data? {
        var buffer = [UInt8](repeating: 0, count: count)
        var totalRead = 0
        while totalRead < count {
            let n = read(fd, &buffer[totalRead], count - totalRead)
            if n <= 0 { return nil }
            totalRead += n
        }
        return Data(buffer)
    }

    private static func sendMessage(fd: Int32, data: Data) {
        var packet = SSHWireFormat.encodeUInt32(UInt32(data.count))
        packet.append(data)
        packet.withUnsafeBytes { buf in
            var written = 0
            while written < buf.count {
                let n = write(fd, buf.baseAddress! + written, buf.count - written)
                if n <= 0 { return }
                written += n
            }
        }
    }
}

// MARK: - Errors

/// Mutable box for bridging Task results out of `syncAwait` to a dispatch semaphore.
private final class ResultBox<T>: @unchecked Sendable {
    var value: T?
}

public enum SSHAgentError: Error, Sendable {
    case socketCreationFailed
    case bindFailed(Int32)
    case listenFailed(Int32)
    case connectionFailed
}
