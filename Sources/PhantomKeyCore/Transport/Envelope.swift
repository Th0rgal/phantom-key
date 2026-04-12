import Foundation

public enum MessageType: UInt8, Sendable, Codable {
    case pairingRequest = 0x01
    case pairingResponse = 0x02
    case pairingConfirm = 0x03
    case makeCredentialRequest = 0x10
    case makeCredentialResponse = 0x11
    case getAssertionRequest = 0x12
    case getAssertionResponse = 0x13
    case getInfoRequest = 0x14
    case getInfoResponse = 0x15
    // CTAP 2.1 credential management
    case credentialManagementRequest = 0x16
    case credentialManagementResponse = 0x17
    // CTAP 2.1 large blob
    case largeBlobRequest = 0x18
    case largeBlobResponse = 0x19
    // Noise NK handshake
    case noiseHandshakeInit = 0x04
    case noiseHandshakeResponse = 0x05
    case policyUpdate = 0x20
    case policyResponse = 0x21
    case keepAlive = 0x30
    case cancel = 0x31
    case error = 0xFF
}

public struct Envelope: Sendable {
    public static let protocolVersion: UInt8 = 1

    public let version: UInt8
    public let type: MessageType
    public let sequence: UInt32
    public let payload: Data

    public init(type: MessageType, sequence: UInt32, payload: Data) {
        self.version = Self.protocolVersion
        self.type = type
        self.sequence = sequence
        self.payload = payload
    }

    public func serialize() -> Data {
        var data = Data()
        data.append(version)
        data.append(type.rawValue)
        var seq = sequence.bigEndian
        data.append(Data(bytes: &seq, count: 4))
        var payloadLen = UInt32(payload.count).bigEndian
        data.append(Data(bytes: &payloadLen, count: 4))
        data.append(payload)
        return data
    }

    public static func deserialize(_ data: Data) throws -> Envelope {
        guard data.count >= 10 else {
            throw EnvelopeError.tooShort
        }

        let version = data[0]
        guard version == protocolVersion else {
            throw EnvelopeError.unsupportedVersion(version)
        }

        guard let type = MessageType(rawValue: data[1]) else {
            throw EnvelopeError.unknownType(data[1])
        }

        let sequence = UInt32(data[2]) << 24 | UInt32(data[3]) << 16
            | UInt32(data[4]) << 8 | UInt32(data[5])

        let payloadLen = Int(UInt32(data[6]) << 24 | UInt32(data[7]) << 16
            | UInt32(data[8]) << 8 | UInt32(data[9]))

        guard data.count >= 10 + payloadLen else {
            throw EnvelopeError.truncatedPayload
        }

        let payload = data[10..<(10 + payloadLen)]

        return Envelope(type: type, sequence: sequence, payload: Data(payload))
    }
}

public enum EnvelopeError: Error, Sendable {
    case tooShort
    case unsupportedVersion(UInt8)
    case unknownType(UInt8)
    case truncatedPayload
}
