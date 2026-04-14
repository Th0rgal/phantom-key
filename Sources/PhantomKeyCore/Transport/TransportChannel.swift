import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

public protocol TransportChannel: Sendable {
    var isConnected: Bool { get async }
    func send(_ data: Data) async throws
    func receive() async throws -> Data
    func disconnect() async
}

public enum TransportError: Error, Sendable {
    case notConnected
    case sendFailed(String)
    case receiveFailed(String)
    case timeout
    case peerDisconnected
}

/// Secure channel using Noise NK-derived separate send/receive CipherState objects.
/// Each direction has its own key and counter-based nonce, preventing nonce reuse.
public actor SecureChannel {
    private let transport: TransportChannel
    private var sendCipher: CipherState
    private var receiveCipher: CipherState
    private var sequenceCounter: UInt32 = 0

    /// Initialize with Noise-derived cipher states (preferred).
    public init(transport: TransportChannel, sendCipher: CipherState, receiveCipher: CipherState) {
        self.transport = transport
        self.sendCipher = sendCipher
        self.receiveCipher = receiveCipher
    }

    /// Initialize with a single shared key (legacy compatibility).
    public init(transport: TransportChannel, sharedKey: SymmetricKeyWrapper) {
        self.transport = transport
        self.sendCipher = CipherState(key: sharedKey.key)
        self.receiveCipher = CipherState(key: sharedKey.key)
    }

    public func send(type: MessageType, payload: Data) async throws {
        let envelope = Envelope(type: type, sequence: sequenceCounter, payload: payload)
        sequenceCounter += 1

        let serialized = envelope.serialize()
        let encrypted = try sendCipher.encrypt(serialized)
        try await transport.send(encrypted)
    }

    public func receive() async throws -> Envelope {
        let encrypted = try await transport.receive()
        let decrypted = try receiveCipher.decrypt(encrypted)
        return try Envelope.deserialize(decrypted)
    }

    public var isConnected: Bool {
        get async { await transport.isConnected }
    }

    public func disconnect() async {
        await transport.disconnect()
    }
}

public struct SymmetricKeyWrapper: @unchecked Sendable {
    public let key: SymmetricKey

    public init(key: SymmetricKey) {
        self.key = key
    }
}
