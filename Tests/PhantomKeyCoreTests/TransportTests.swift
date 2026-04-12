import Testing
import Foundation
@testable import PhantomKeyCore

@Suite("Transport Envelope")
struct TransportTests {
    @Test("Envelope serialize and deserialize roundtrip")
    func envelopeRoundtrip() throws {
        let payload = Data("test payload data".utf8)
        let envelope = Envelope(type: .getAssertionRequest, sequence: 42, payload: payload)

        let serialized = envelope.serialize()
        let deserialized = try Envelope.deserialize(serialized)

        #expect(deserialized.version == Envelope.protocolVersion)
        #expect(deserialized.type == .getAssertionRequest)
        #expect(deserialized.sequence == 42)
        #expect(deserialized.payload == payload)
    }

    @Test("Envelope with empty payload")
    func emptyPayload() throws {
        let envelope = Envelope(type: .keepAlive, sequence: 0, payload: Data())
        let serialized = envelope.serialize()
        let deserialized = try Envelope.deserialize(serialized)

        #expect(deserialized.payload.isEmpty)
        #expect(deserialized.type == .keepAlive)
    }

    @Test("Envelope with large payload")
    func largePayload() throws {
        let payload = Data(repeating: 0xAB, count: 4096)
        let envelope = Envelope(type: .makeCredentialResponse, sequence: 999, payload: payload)

        let serialized = envelope.serialize()
        let deserialized = try Envelope.deserialize(serialized)

        #expect(deserialized.payload == payload)
        #expect(deserialized.sequence == 999)
    }

    @Test("Envelope reject truncated data")
    func truncatedData() {
        let short = Data(repeating: 0, count: 5)
        #expect(throws: EnvelopeError.self) {
            try Envelope.deserialize(short)
        }
    }

    @Test("Envelope reject wrong version")
    func wrongVersion() {
        var data = Data(repeating: 0, count: 10)
        data[0] = 99 // bad version
        #expect(throws: EnvelopeError.self) {
            try Envelope.deserialize(data)
        }
    }

    @Test("All message types have unique raw values")
    func uniqueMessageTypes() {
        let types: [MessageType] = [
            .pairingRequest, .pairingResponse, .pairingConfirm,
            .makeCredentialRequest, .makeCredentialResponse,
            .getAssertionRequest, .getAssertionResponse,
            .getInfoRequest, .getInfoResponse,
            .policyUpdate, .policyResponse,
            .keepAlive, .cancel, .error,
        ]
        let rawValues = types.map(\.rawValue)
        #expect(Set(rawValues).count == rawValues.count)
    }

    @Test("Pairing data QR payload roundtrip")
    func pairingDataRoundtrip() throws {
        let original = PairingData(
            publicKey: Data(repeating: 0xAA, count: 32),
            pairingCode: "123456",
            serviceUUID: "TEST-UUID-1234",
            deviceName: "Test Mac"
        )

        let qrPayload = try original.toQRPayload()
        let restored = try PairingData.fromQRPayload(qrPayload)

        #expect(restored.publicKey == original.publicKey)
        #expect(restored.pairingCode == original.pairingCode)
        #expect(restored.serviceUUID == original.serviceUUID)
        #expect(restored.deviceName == original.deviceName)
    }

    @Test("Pairing initiator and responder derive same secret")
    func pairingFlow() throws {
        let initiator = PairingInitiator()
        let responder = PairingResponder()

        let qrData = initiator.qrData
        let deviceId = "test-device-id"

        let initiatorPaired = try initiator.completePairing(
            remotePublicKey: responder.publicKeyData,
            deviceId: deviceId,
            deviceName: "Test iPhone"
        )

        let responderPaired = try responder.completePairing(
            scannedData: qrData,
            deviceId: "mac-id"
        )

        #expect(initiatorPaired.sharedSecret == responderPaired.sharedSecret)
    }
}

@Suite("HID Message Assembly")
struct HIDMessageTests {
    let assembler = HIDMessageAssembler()

    @Test("Build and parse init packet")
    func initPacketRoundtrip() {
        let channelId: UInt32 = 0xDEADBEEF
        let data = Data([CTAPStatusCode.ok.rawValue])

        let packets = assembler.buildResponse(
            channelId: channelId,
            command: HIDCommandByte.cbor.rawValue,
            data: data
        )

        #expect(packets.count == 1)
        #expect(packets[0].count == 64)

        if let parsed = assembler.parseInitPacket(packets[0]) {
            #expect(parsed.channelId == channelId)
            #expect(parsed.command == HIDCommandByte.cbor.rawValue)
            #expect(parsed.totalLength == data.count)
        } else {
            Issue.record("Failed to parse init packet")
        }
    }

    @Test("Large message splits into multiple packets")
    func multiPacketMessage() {
        let channelId: UInt32 = 0x12345678
        let data = Data(repeating: 0xCC, count: 200)

        let packets = assembler.buildResponse(
            channelId: channelId,
            command: HIDCommandByte.cbor.rawValue,
            data: data
        )

        #expect(packets.count > 1)
        for packet in packets {
            #expect(packet.count == 64)
        }
    }

    @Test("Init response serialization")
    func initResponseSerialization() {
        let nonce = Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        let response = HIDInitResponse(nonce: nonce, channelId: 0x00000001)

        let serialized = response.serialize()
        #expect(serialized.count == 17) // 8 nonce + 4 CID + 5 version info
        #expect(Data(serialized.prefix(8)) == nonce)
    }
}
