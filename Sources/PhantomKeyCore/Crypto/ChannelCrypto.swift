import Foundation
import Crypto

public struct PairingKeys: @unchecked Sendable {
    public let localPrivateKey: Curve25519.KeyAgreement.PrivateKey
    public let localPublicKey: Curve25519.KeyAgreement.PublicKey

    public init() {
        self.localPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        self.localPublicKey = localPrivateKey.publicKey
    }

    public var publicKeyData: Data {
        localPublicKey.rawRepresentation
    }

    public func deriveSharedSecret(remotePublicKey: Data) throws -> SymmetricKey {
        guard remotePublicKey.count == 32 else {
            throw ChannelCryptoError.invalidPublicKey
        }
        let remotePub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: remotePublicKey)
        let shared = try localPrivateKey.sharedSecretFromKeyAgreement(with: remotePub)
        return shared.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data("PhantomKey-v1".utf8),
            sharedInfo: Data("channel-encryption".utf8),
            outputByteCount: 32
        )
    }

    public static func generatePairingCode() -> String {
        let code = (0..<6).map { _ in String(Int.random(in: 0...9)) }.joined()
        return code
    }
}

public struct ChannelEncryptor: @unchecked Sendable {
    private let key: SymmetricKey

    public init(sharedKey: SymmetricKey) {
        self.key = sharedKey
    }

    public func encrypt(_ plaintext: Data) throws -> Data {
        let nonce = AES.GCM.Nonce()
        let sealed = try AES.GCM.seal(plaintext, using: key, nonce: nonce)
        var result = Data()
        result.append(contentsOf: nonce)
        result.append(sealed.ciphertext)
        result.append(sealed.tag)
        return result
    }

    public func decrypt(_ data: Data) throws -> Data {
        guard data.count >= 28 else {
            throw ChannelCryptoError.messageTooShort
        }

        let nonceData = data.prefix(12)
        let tagStart = data.count - 16
        let ciphertext = data[12..<tagStart]
        let tag = data[tagStart...]

        let nonce = try AES.GCM.Nonce(data: nonceData)
        let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        return try AES.GCM.open(sealedBox, using: key)
    }
}

public enum ChannelCryptoError: Error, Sendable {
    case messageTooShort
    case decryptionFailed
    case invalidPublicKey
}
