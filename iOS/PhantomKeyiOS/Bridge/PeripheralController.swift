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

    // L2CAP channel for high-throughput transfers (large blobs, bulk credential ops)
    private var l2capChannel: CBL2CAPChannel?
    private var l2capPSM: CBL2CAPPSM?

    static let restoreIdentifier = "md.thomas.phantomkey.peripheral"
    static let serviceUUID = CBUUID(string: "A1B2C3D4-E5F6-7890-ABCD-F1D0AE000000")
    static let writeCharUUID = CBUUID(string: "A1B2C3D4-E5F6-7890-ABCD-F1D0AE000001")
    static let readCharUUID = CBUUID(string: "A1B2C3D4-E5F6-7890-ABCD-F1D0AE000002")

    @Published var isAdvertising = false
    @Published var connectedDevice: String?
    @Published var l2capReady = false

    init(policyEngine: PolicyEngine) {
        self.policyEngine = policyEngine
        super.init()
    }

    func start() {
        // Use state restoration to survive background kills
        peripheralManager = CBPeripheralManager(
            delegate: self,
            queue: .main,
            options: [
                CBPeripheralManagerOptionRestoreIdentifierKey: Self.restoreIdentifier,
                CBPeripheralManagerOptionShowPowerAlertKey: true,
            ]
        )
    }

    func stop() {
        closeL2CAPChannel()
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

    // MARK: - L2CAP Channel Management

    /// Publish an L2CAP channel for high-throughput data transfer.
    func publishL2CAPChannel() {
        peripheralManager?.publishL2CAPChannel(withEncryption: true)
    }

    private func closeL2CAPChannel() {
        if let psm = l2capPSM {
            peripheralManager?.unpublishL2CAPChannel(psm)
        }
        l2capChannel = nil
        l2capPSM = nil
        l2capReady = false
    }

    /// Send data over L2CAP if available, otherwise fall back to GATT characteristic.
    func sendResponse(_ data: Data) {
        if let channel = l2capChannel {
            channel.outputStream.write([UInt8](data), maxLength: data.count)
        } else {
            sendViaCharacteristic(data)
        }
    }

    private func sendViaCharacteristic(_ data: Data) {
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
                case .credentialManagementRequest:
                    // Forward to credential management handler
                    try await channel.send(type: .credentialManagementResponse, payload: Data())
                case .largeBlobRequest:
                    // Forward to large blob handler
                    try await channel.send(type: .largeBlobResponse, payload: Data())
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
            await requestUserApproval(for: envelope)
        }
    }

    private func requestUserApproval(for envelope: Envelope) async {
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
            publishL2CAPChannel()
        case .poweredOff:
            isAdvertising = false
            l2capReady = false
        default:
            break
        }
    }

    /// CoreBluetooth state restoration callback. Re-establish services after background kill.
    func peripheralManager(_ peripheral: CBPeripheralManager,
                           willRestoreState dict: [String: Any]) {
        if let services = dict[CBPeripheralManagerRestoredStateServicesKey] as? [CBMutableService] {
            for restored in services {
                if restored.uuid == Self.serviceUUID {
                    service = restored
                    for char in restored.characteristics ?? [] {
                        if char.uuid == Self.writeCharUUID {
                            writeCharacteristic = char as? CBMutableCharacteristic
                        } else if char.uuid == Self.readCharUUID {
                            readCharacteristic = char as? CBMutableCharacteristic
                        }
                    }
                }
            }
        }

        if let advertisingData = dict[CBPeripheralManagerRestoredStateAdvertisementDataKey] as? [String: Any] {
            isAdvertising = !advertisingData.isEmpty
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

    // MARK: - L2CAP Delegate Methods

    func peripheralManager(_ peripheral: CBPeripheralManager,
                           didPublishL2CAPChannel PSM: CBL2CAPPSM, error: Error?) {
        if let error = error {
            print("L2CAP publish failed: \(error.localizedDescription)")
            return
        }
        l2capPSM = PSM
    }

    func peripheralManager(_ peripheral: CBPeripheralManager,
                           didOpen channel: CBL2CAPChannel?, error: Error?) {
        if let error = error {
            print("L2CAP open failed: \(error.localizedDescription)")
            return
        }
        l2capChannel = channel
        l2capReady = true
    }
}

extension Notification.Name {
    static let phantomKeyApprovalRequired = Notification.Name("phantomKeyApprovalRequired")
}
#endif
