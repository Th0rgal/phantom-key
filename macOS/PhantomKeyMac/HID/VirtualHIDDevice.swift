#if canImport(DriverKit) || canImport(HIDDriverKit)
import Foundation
import PhantomKeyCore

// DriverKit virtual HID device for FIDO2/CTAP2
//
// This creates a virtual HID device on usage page 0xF1D0 (FIDO Alliance).
// Browsers (Chrome, Firefox, Safari) and OpenSSH/libfido2 discover it
// automatically as a security key.
//
// Requires:
// - DriverKit entitlement: com.apple.developer.driverkit.family.hid.device
// - System Extension approval in System Settings
// - Notarization for distribution
//
// The actual DriverKit driver must be built as a separate .systemextension
// target in Xcode. This file contains the userspace controller that
// communicates with the driver.

class VirtualHIDController {
    private let bridgeController: BridgeController
    private let messageAssembler = HIDMessageAssembler()
    private var channelCounter: UInt32 = 1

    init(bridge: BridgeController) {
        self.bridgeController = bridge
    }

    func handleHIDReport(_ report: Data) async throws -> [Data] {
        guard let parsed = messageAssembler.parseInitPacket(report) else {
            return []
        }

        let command = parsed.command

        if command == HIDCommandByte.initialize.rawValue {
            return handleInit(channelId: parsed.channelId, payload: parsed.payload)
        }

        if command == HIDCommandByte.cbor.rawValue {
            return try await handleCBOR(channelId: parsed.channelId, payload: parsed.payload)
        }

        if command == HIDCommandByte.ping.rawValue {
            return messageAssembler.buildResponse(
                channelId: parsed.channelId,
                command: HIDCommandByte.ping.rawValue,
                data: parsed.payload
            )
        }

        if command == HIDCommandByte.cancel.rawValue {
            return []
        }

        return buildErrorResponse(channelId: parsed.channelId, code: .invalidCommand)
    }

    private func handleInit(channelId: UInt32, payload: Data) -> [Data] {
        channelCounter += 1

        let response = HIDInitResponse(
            nonce: payload.prefix(8),
            channelId: channelCounter,
            capabilities: HIDInitResponse.capabilityCBOR
        )

        return messageAssembler.buildResponse(
            channelId: channelId,
            command: HIDCommandByte.initialize.rawValue,
            data: response.serialize()
        )
    }

    private func handleCBOR(channelId: UInt32, payload: Data) async throws -> [Data] {
        guard !payload.isEmpty else {
            return buildErrorResponse(channelId: channelId, code: .invalidLength)
        }

        let ctapCommand = payload[0]
        let ctapData = payload.dropFirst()

        switch ctapCommand {
        case CTAPCommandType.getInfo.rawValue:
            let info = AuthenticatorInfo.phantomKey.toCBOR()
            let encoder = CBOREncoder()
            var responseData = Data([CTAPStatusCode.ok.rawValue])
            responseData.append(encoder.encode(info))
            return messageAssembler.buildResponse(
                channelId: channelId,
                command: HIDCommandByte.cbor.rawValue,
                data: responseData
            )

        case CTAPCommandType.makeCredential.rawValue,
             CTAPCommandType.getAssertion.rawValue:
            let responsePayload = try await bridgeController.forwardCTAPRequest(payload)
            return messageAssembler.buildResponse(
                channelId: channelId,
                command: HIDCommandByte.cbor.rawValue,
                data: responsePayload
            )

        default:
            return buildErrorResponse(channelId: channelId, code: .invalidCommand)
        }
    }

    private func buildErrorResponse(channelId: UInt32, code: CTAPStatusCode) -> [Data] {
        messageAssembler.buildResponse(
            channelId: channelId,
            command: HIDCommandByte.error.rawValue,
            data: Data([code.rawValue])
        )
    }
}
#endif
