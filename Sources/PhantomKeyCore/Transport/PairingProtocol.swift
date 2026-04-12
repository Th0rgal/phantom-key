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

/// Pairing initiator (Mac side). Generates a static X25519 key pair for Noise NK.
/// The public key is shared via QR code; the private key is stored for future sessions.
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

    /// Start a Noise NK handshake as the initiator.
    /// The responder's static public key comes from the paired device record.
    public func beginNoiseHandshake(
        responderStaticPublic: Data
    ) throws -> (message: Data, pending: PendingInitiator) {
        try NoiseNK.initiator(responderStaticPublic: responderStaticPublic)
    }

    /// Finalize the Noise NK handshake after receiving the responder's reply.
    public func finalizeNoiseHandshake(
        pending: inout PendingInitiator,
        response: Data
    ) throws -> (sendCipher: CipherState, receiveCipher: CipherState) {
        try NoiseNK.initiatorFinalize(
            pendingEphemeralPrivate: pending.ephemeralPrivate,
            symmetricState: &pending.symmetricState,
            responseMessage: response
        )
    }

    private func generateServiceUUID() -> String {
        let hex = (0..<4).map { _ in String(format: "%04X", UInt16.random(in: 0...UInt16.max)) }
        return "\(hex[0])\(hex[1])-\(hex[2])-\(hex[3])-AAAA-F1D0AE000000"
    }
}

/// Pairing responder (iPhone side). The iPhone holds a static X25519 key pair.
public struct PairingResponder: @unchecked Sendable {
    private let keys: PairingKeys
    public let staticPrivateKey: Curve25519.KeyAgreement.PrivateKey

    public init() {
        self.keys = PairingKeys()
        self.staticPrivateKey = keys.localPrivateKey
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

    /// Process a Noise NK handshake message from the initiator and derive cipher states.
    public func processNoiseHandshake(
        message: Data
    ) throws -> (response: Data, sendCipher: CipherState, receiveCipher: CipherState) {
        try NoiseNK.responder(staticPrivateKey: staticPrivateKey, message: message)
    }
}
