#if canImport(CoreBluetooth)
import Foundation
import CoreBluetooth
import PhantomKeyCore

class PeripheralController: NSObject, ObservableObject {
    private var peripheralManager: CBPeripheralManager?
    private var service: CBMutableService?
    private var writeCharacteristic: CBMutableCharacteristic?
    private var readCharacteristic: CBMutableCharacteristic?
    private var subscribedCentral: CBCentral?

    private let policyEngine: PolicyEngine
    private var secureChannel: SecureChannel?
    private var pendingData = Data()

    static let serviceUUID = CBUUID(string: "A1B2C3D4-E5F6-7890-ABCD-PHANTOMKEY00")
    static let writeCharUUID = CBUUID(string: "A1B2C3D4-E5F6-7890-ABCD-PHANTOMKEY01")
    static let readCharUUID = CBUUID(string: "A1B2C3D4-E5F6-7890-ABCD-PHANTOMKEY02")

    @Published var isAdvertising = false
    @Published var connectedDevice: String?

    init(policyEngine: PolicyEngine) {
        self.policyEngine = policyEngine
        super.init()
    }

    func start() {
        peripheralManager = CBPeripheralManager(delegate: self, queue: .main)
    }

    func stop() {
        peripheralManager?.stopAdvertising()
        peripheralManager?.removeAllServices()
        isAdvertising = false
    }

    private func setupService() {
        writeCharacteristic = CBMutableCharacteristic(
            type: Self.writeCharUUID,
            properties: [.write, .writeWithoutResponse],
            value: nil,
            permissions: [.writeable]
        )

        readCharacteristic = CBMutableCharacteristic(
            type: Self.readCharUUID,
            properties: [.notify, .read],
            value: nil,
            permissions: [.readable]
        )

        service = CBMutableService(type: Self.serviceUUID, primary: true)
        service?.characteristics = [writeCharacteristic!, readCharacteristic!]

        peripheralManager?.add(service!)
    }

    private func startAdvertising() {
        peripheralManager?.startAdvertising([
            CBAdvertisementDataServiceUUIDsKey: [Self.serviceUUID],
            CBAdvertisementDataLocalNameKey: "PhantomKey",
        ])
        isAdvertising = true
    }

    private func sendResponse(_ data: Data) {
        guard let characteristic = readCharacteristic,
              let central = subscribedCentral else { return }
        peripheralManager?.updateValue(data, for: characteristic, onSubscribedCentrals: [central])
    }

    private func handleIncomingRequest(_ data: Data) {
        Task {
            do {
                guard let channel = secureChannel else { return }

                let envelope = try await channel.receive()

                switch envelope.type {
                case .makeCredentialRequest, .getAssertionRequest:
                    await processSigningRequest(envelope)
                case .getInfoRequest:
                    let info = AuthenticatorInfo.phantomKey.toCBOR()
                    let responseData = CBOREncoder().encode(info)
                    try await channel.send(type: .getInfoResponse, payload: responseData)
                default:
                    break
                }
            } catch {
                // Log error
            }
        }
    }

    private func processSigningRequest(_ envelope: Envelope) async {
        let rpId = extractRelyingPartyId(from: envelope.payload)
        let decision = await policyEngine.evaluate(relyingPartyId: rpId, requiresUV: true)

        switch decision {
        case .approve:
            await policyEngine.recordApproval(relyingPartyId: rpId)
            // Sign and respond
        case .deny:
            try? await secureChannel?.send(type: .error, payload: Data([CTAPStatusCode.operationDenied.rawValue]))
        case .requireUserPresence, .requireUserVerification:
            // Trigger Face ID / Touch ID prompt via notification
            await requestUserApproval(for: envelope)
        }
    }

    private func requestUserApproval(for envelope: Envelope) async {
        // Post notification to trigger approval UI
        DispatchQueue.main.async {
            NotificationCenter.default.post(
                name: .phantomKeyApprovalRequired,
                object: nil,
                userInfo: ["envelope": envelope.payload]
            )
        }
    }

    private func extractRelyingPartyId(from data: Data) -> String {
        let decoder = CBORDecoder()
        guard let cbor = try? decoder.decode(data) else { return "unknown" }
        if case .map(let pairs) = cbor {
            for (key, value) in pairs {
                if case .unsignedInt(2) = key, case .textString(let rpId) = value {
                    return rpId
                }
            }
        }
        return "unknown"
    }
}

extension PeripheralController: CBPeripheralManagerDelegate {
    func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        switch peripheral.state {
        case .poweredOn:
            setupService()
            startAdvertising()
        case .poweredOff:
            isAdvertising = false
        default:
            break
        }
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, didReceiveWrite requests: [CBATTRequest]) {
        for request in requests {
            if request.characteristic.uuid == Self.writeCharUUID, let data = request.value {
                handleIncomingRequest(data)
            }
            peripheral.respond(to: request, withResult: .success)
        }
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral,
                           didSubscribeTo characteristic: CBCharacteristic) {
        subscribedCentral = central
        connectedDevice = "Mac (\(central.identifier.uuidString.prefix(8)))"
    }

    func peripheralManager(_ peripheral: CBPeripheralManager, central: CBCentral,
                           didUnsubscribeFrom characteristic: CBCharacteristic) {
        if central.identifier == subscribedCentral?.identifier {
            subscribedCentral = nil
            connectedDevice = nil
        }
    }
}

extension Notification.Name {
    static let phantomKeyApprovalRequired = Notification.Name("phantomKeyApprovalRequired")
}
#endif
