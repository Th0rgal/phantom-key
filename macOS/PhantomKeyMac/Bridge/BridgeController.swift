#if canImport(CoreBluetooth)
import Foundation
import CoreBluetooth
import PhantomKeyCore

class BridgeController: NSObject, ObservableObject {
    private var centralManager: CBCentralManager?
    private var connectedPeripheral: CBPeripheral?
    private var writeCharacteristic: CBCharacteristic?
    private var readCharacteristic: CBCharacteristic?
    private var secureChannel: SecureChannel?

    static let serviceUUID = CBUUID(string: "A1B2C3D4-E5F6-7890-ABCD-F1D0AE000000")
    static let writeCharUUID = CBUUID(string: "A1B2C3D4-E5F6-7890-ABCD-F1D0AE000001")
    static let readCharUUID = CBUUID(string: "A1B2C3D4-E5F6-7890-ABCD-F1D0AE000002")

    @Published var connectionState: ConnectionState = .disconnected
    @Published var lastActivity: String = ""

    enum ConnectionState: String {
        case disconnected = "Disconnected"
        case scanning = "Scanning..."
        case connecting = "Connecting..."
        case connected = "Connected"
        case paired = "Paired & Ready"
    }

    override init() {
        super.init()
    }

    func start() {
        centralManager = CBCentralManager(delegate: self, queue: .main)
    }

    func stop() {
        centralManager?.stopScan()
        if let peripheral = connectedPeripheral {
            centralManager?.cancelPeripheralConnection(peripheral)
        }
        connectionState = .disconnected
    }

    private func startScanning() {
        connectionState = .scanning
        centralManager?.scanForPeripherals(
            withServices: [Self.serviceUUID],
            options: [CBCentralManagerScanOptionAllowDuplicatesKey: false]
        )
    }

    func forwardCTAPRequest(_ request: Data) async throws -> Data {
        guard let channel = secureChannel else {
            throw TransportError.notConnected
        }

        try await channel.send(type: .getAssertionRequest, payload: request)
        let response = try await channel.receive()
        return response.payload
    }
}

extension BridgeController: CBCentralManagerDelegate {
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        switch central.state {
        case .poweredOn:
            startScanning()
        case .poweredOff:
            connectionState = .disconnected
        default:
            break
        }
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                        advertisementData: [String: Any], rssi RSSI: NSNumber) {
        central.stopScan()
        connectedPeripheral = peripheral
        connectionState = .connecting
        central.connect(peripheral, options: nil)
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        connectionState = .connected
        peripheral.delegate = self
        peripheral.discoverServices([Self.serviceUUID])
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        connectedPeripheral = nil
        connectionState = .disconnected
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) { [weak self] in
            self?.startScanning()
        }
    }
}

extension BridgeController: CBPeripheralDelegate {
    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard let services = peripheral.services else { return }
        for service in services {
            peripheral.discoverCharacteristics(
                [Self.writeCharUUID, Self.readCharUUID],
                for: service
            )
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        guard let characteristics = service.characteristics else { return }
        for char in characteristics {
            if char.uuid == Self.writeCharUUID {
                writeCharacteristic = char
            } else if char.uuid == Self.readCharUUID {
                readCharacteristic = char
                peripheral.setNotifyValue(true, for: char)
            }
        }

        if writeCharacteristic != nil && readCharacteristic != nil {
            connectionState = .paired
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard characteristic.uuid == Self.readCharUUID,
              let data = characteristic.value else { return }
        lastActivity = "Received \(data.count) bytes"
    }
}
#endif
