#if canImport(IOKit)
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

    // In-progress multi-packet message state
    private var pendingChannelId: UInt32 = 0
    private var pendingCommand: UInt8 = 0
    private var pendingTotalLength: Int = 0
    private var pendingData: Data = Data()
    private var pendingNextSeq: UInt8 = 0

    init(bridge: BridgeController) {
        self.bridgeController = bridge
    }

    func handleHIDReport(_ report: Data) async throws -> [Data] {
        guard report.count >= 5 else { return [] }

        // CTAPHID spec: high bit set on byte 4 means init packet, clear means continuation
        if report[4] & 0x80 != 0 {
            // Init packet — start a new message
            guard let parsed = messageAssembler.parseInitPacket(report) else { return [] }

            // Discard any in-progress partial message (even from a different channel)
            pendingChannelId = parsed.channelId
            pendingCommand = parsed.command
            pendingTotalLength = parsed.totalLength
            pendingData = parsed.payload
            pendingNextSeq = 0

            // If init payload already satisfies totalLength, process immediately
            if pendingData.count >= pendingTotalLength {
                return try await dispatchMessage(
                    channelId: pendingChannelId,
                    command: pendingCommand,
                    payload: Data(pendingData.prefix(pendingTotalLength))
                )
            }

            // Otherwise wait for continuation packets
            return []

        } else {
            // Continuation packet
            guard let cont = messageAssembler.parseContPacket(report) else { return [] }

            // Ignore packets that don't belong to the current in-progress message
            guard cont.channelId == pendingChannelId, cont.seq == pendingNextSeq else {
                return []
            }

            pendingData.append(cont.payload)
            pendingNextSeq += 1

            if pendingData.count >= pendingTotalLength {
                return try await dispatchMessage(
                    channelId: pendingChannelId,
                    command: pendingCommand,
                    payload: Data(pendingData.prefix(pendingTotalLength))
                )
            }

            // Still waiting for more continuation packets
            return []
        }
    }

    private func dispatchMessage(channelId: UInt32, command: UInt8, payload: Data) async throws -> [Data] {
        // Clear pending state
        pendingChannelId = 0
        pendingData = Data()

        if command == HIDCommandByte.initialize.rawValue {
            return handleInit(channelId: channelId, payload: payload)
        }

        if command == HIDCommandByte.cbor.rawValue {
            return try await handleCBOR(channelId: channelId, payload: payload)
        }

        if command == HIDCommandByte.ping.rawValue {
            return messageAssembler.buildResponse(
                channelId: channelId,
                command: HIDCommandByte.ping.rawValue,
                data: payload
            )
        }

        if command == HIDCommandByte.cancel.rawValue {
            return []
        }

        return buildErrorResponse(channelId: channelId, code: .invalidCommand)
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
