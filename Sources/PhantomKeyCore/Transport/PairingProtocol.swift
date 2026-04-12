import Foundation
import Crypto

public struct PairingData: Sendable, Codable {
    public let publicKey: Data
    public let pairingCode: String
    public let serviceUUID: String
    public let deviceName: String
    public let timestamp: Date

    public init(publicKey: Data, pairingCode: String, serviceUUID: String, deviceName: String) {
        self.publicKey = publicKey
        self.pairingCode = pairingCode
        self.serviceUUID = serviceUUID
        self.deviceName = deviceName
        self.timestamp = Date()
    }

    public func toQRPayload() throws -> Data {
        try JSONEncoder().encode(self)
    }

    public static func fromQRPayload(_ data: Data) throws -> PairingData {
        try JSONDecoder().decode(PairingData.self, from: data)
    }
}

public struct PairedDevice: Sendable, Codable {
    public let deviceId: String
    public let deviceName: String
    public let sharedSecret: Data
    public let serviceUUID: String
    public let pairedAt: Date

    public init(deviceId: String, deviceName: String, sharedSecret: Data, serviceUUID: String) {
        self.deviceId = deviceId
        self.deviceName = deviceName
        self.sharedSecret = sharedSecret
        self.serviceUUID = serviceUUID
        self.pairedAt = Date()
    }
}

public struct PairingInitiator: Sendable {
    private let keys: PairingKeys
    private let pairingCode: String

    public init() {
        self.keys = PairingKeys()
        self.pairingCode = PairingKeys.generatePairingCode()
    }

    public var qrData: PairingData {
        PairingData(
            publicKey: keys.publicKeyData,
            pairingCode: pairingCode,
            serviceUUID: generateServiceUUID(),
            deviceName: "PhantomKey Mac"
        )
    }

    public var displayCode: String { pairingCode }

    public func completePairing(remotePublicKey: Data, deviceId: String, deviceName: String) throws -> PairedDevice {
        let sharedKey = try keys.deriveSharedSecret(remotePublicKey: remotePublicKey)
        let keyData = sharedKey.withUnsafeBytes { Data($0) }

        return PairedDevice(
            deviceId: deviceId,
            deviceName: deviceName,
            sharedSecret: keyData,
            serviceUUID: qrData.serviceUUID
        )
    }

    private func generateServiceUUID() -> String {
        let hex = (0..<4).map { _ in String(format: "%04X", UInt16.random(in: 0...UInt16.max)) }
        return "\(hex[0])\(hex[1])-\(hex[2])-\(hex[3])-AAAA-F1D0AE000000"
    }
}

public struct PairingResponder: Sendable {
    private let keys: PairingKeys

    public init() {
        self.keys = PairingKeys()
    }

    public var publicKeyData: Data { keys.publicKeyData }

    public func completePairing(scannedData: PairingData, deviceId: String) throws -> PairedDevice {
        let sharedKey = try keys.deriveSharedSecret(remotePublicKey: scannedData.publicKey)
        let keyData = sharedKey.withUnsafeBytes { Data($0) }

        return PairedDevice(
            deviceId: deviceId,
            deviceName: scannedData.deviceName,
            sharedSecret: keyData,
            serviceUUID: scannedData.serviceUUID
        )
    }
}
