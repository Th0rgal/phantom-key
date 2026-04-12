import Foundation

public enum HIDCommandByte: UInt8, Sendable {
    case msg = 0x03
    case cbor = 0x10
    case initialize = 0x06
    case ping = 0x01
    case cancel = 0x11
    case keepAlive = 0x3B
    case error = 0x3F
    case wink = 0x08
}

public struct HIDInitRequest: Sendable {
    public static let broadcastCID: UInt32 = 0xFFFFFFFF
    public let nonce: Data

    public init(nonce: Data) {
        self.nonce = nonce
    }
}

public struct HIDInitResponse: Sendable {
    public let nonce: Data
    public let channelId: UInt32
    public let protocolVersion: UInt8
    public let majorVersion: UInt8
    public let minorVersion: UInt8
    public let buildVersion: UInt8
    public let capabilities: UInt8

    public static let capabilityWink: UInt8 = 0x01
    public static let capabilityCBOR: UInt8 = 0x04
    public static let capabilityNoMsgCmd: UInt8 = 0x08

    public init(
        nonce: Data,
        channelId: UInt32,
        protocolVersion: UInt8 = 2,
        majorVersion: UInt8 = 1,
        minorVersion: UInt8 = 0,
        buildVersion: UInt8 = 1,
        capabilities: UInt8 = 0x04
    ) {
        self.nonce = nonce
        self.channelId = channelId
        self.protocolVersion = protocolVersion
        self.majorVersion = majorVersion
        self.minorVersion = minorVersion
        self.buildVersion = buildVersion
        self.capabilities = capabilities
    }

    public func serialize() -> Data {
        var data = Data()
        data.append(nonce)
        var cid = channelId.bigEndian
        data.append(Data(bytes: &cid, count: 4))
        data.append(protocolVersion)
        data.append(majorVersion)
        data.append(minorVersion)
        data.append(buildVersion)
        data.append(capabilities)
        return data
    }
}

public struct HIDMessageAssembler: Sendable {
    public static let reportSize = 64
    private static let initHeaderSize = 7
    private static let contHeaderSize = 5

    public init() {}

    public func parseInitPacket(_ data: Data) -> (channelId: UInt32, command: UInt8, totalLength: Int, payload: Data)? {
        guard data.count >= Self.initHeaderSize else { return nil }

        let cid = UInt32(data[0]) << 24 | UInt32(data[1]) << 16 | UInt32(data[2]) << 8 | UInt32(data[3])
        let cmd = data[4] & 0x7F
        let len = Int(data[5]) << 8 | Int(data[6])
        let payload = data.suffix(from: 7).prefix(min(len, Self.reportSize - Self.initHeaderSize))

        return (cid, cmd, len, Data(payload))
    }

    public func parseContPacket(_ data: Data) -> (channelId: UInt32, seq: UInt8, payload: Data)? {
        guard data.count >= Self.contHeaderSize else { return nil }

        let cid = UInt32(data[0]) << 24 | UInt32(data[1]) << 16 | UInt32(data[2]) << 8 | UInt32(data[3])
        let seq = data[4]
        let payload = data.suffix(from: 5)

        return (cid, seq, Data(payload))
    }

    public func buildResponse(channelId: UInt32, command: UInt8, data: Data) -> [Data] {
        var packets: [Data] = []
        var offset = 0

        var initPacket = Data(repeating: 0, count: Self.reportSize)
        initPacket[0] = UInt8((channelId >> 24) & 0xFF)
        initPacket[1] = UInt8((channelId >> 16) & 0xFF)
        initPacket[2] = UInt8((channelId >> 8) & 0xFF)
        initPacket[3] = UInt8(channelId & 0xFF)
        initPacket[4] = command | 0x80
        initPacket[5] = UInt8((data.count >> 8) & 0xFF)
        initPacket[6] = UInt8(data.count & 0xFF)

        let initPayloadSize = min(data.count, Self.reportSize - Self.initHeaderSize)
        if initPayloadSize > 0 {
            initPacket.replaceSubrange(7..<(7 + initPayloadSize), with: data[0..<initPayloadSize])
        }
        packets.append(initPacket)
        offset = initPayloadSize

        var seq: UInt8 = 0
        while offset < data.count {
            var contPacket = Data(repeating: 0, count: Self.reportSize)
            contPacket[0] = UInt8((channelId >> 24) & 0xFF)
            contPacket[1] = UInt8((channelId >> 16) & 0xFF)
            contPacket[2] = UInt8((channelId >> 8) & 0xFF)
            contPacket[3] = UInt8(channelId & 0xFF)
            contPacket[4] = seq

            let contPayloadSize = min(data.count - offset, Self.reportSize - Self.contHeaderSize)
            contPacket.replaceSubrange(5..<(5 + contPayloadSize), with: data[offset..<(offset + contPayloadSize)])
            packets.append(contPacket)

            offset += contPayloadSize
            seq += 1
        }

        return packets
    }
}
