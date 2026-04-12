import Foundation

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

public actor SecureChannel {
    private let transport: TransportChannel
    private let encryptor: ChannelEncryptor
    private var sequenceCounter: UInt32 = 0

    public init(transport: TransportChannel, sharedKey: SymmetricKeyWrapper) {
        self.transport = transport
        self.encryptor = ChannelEncryptor(sharedKey: sharedKey.key)
    }

    public func send(type: MessageType, payload: Data) async throws {
        let envelope = Envelope(type: type, sequence: sequenceCounter, payload: payload)
        sequenceCounter += 1

        let serialized = envelope.serialize()
        let encrypted = try encryptor.encrypt(serialized)
        try await transport.send(encrypted)
    }

    public func receive() async throws -> Envelope {
        let encrypted = try await transport.receive()
        let decrypted = try encryptor.decrypt(encrypted)
        return try Envelope.deserialize(decrypted)
    }

    public var isConnected: Bool {
        get async { await transport.isConnected }
    }

    public func disconnect() async {
        await transport.disconnect()
    }
}

import Crypto

public struct SymmetricKeyWrapper: @unchecked Sendable {
    public let key: SymmetricKey

    public init(key: SymmetricKey) {
        self.key = key
    }
}
