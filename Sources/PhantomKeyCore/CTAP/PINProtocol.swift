import Foundation
import Crypto

public enum PINProtocolVersion: Int, Sendable, Codable {
    case v1 = 1
    case v2 = 2
}

public protocol PINUVAuthProtocol: Sendable {
    var version: PINProtocolVersion { get }
    func authenticate(key: Data, message: Data) -> Data
    func verify(key: Data, message: Data, signature: Data) -> Bool
}

/// PIN/UV Auth Protocol v1 (CTAP 2.0)
/// Uses HMAC-SHA-256 truncated to 16 bytes for authentication.
public struct PINProtocolV1: PINUVAuthProtocol, Sendable {
    public let version = PINProtocolVersion.v1

    public init() {}

    public func authenticate(key: Data, message: Data) -> Data {
        let hmac = HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key))
        return Data(hmac.prefix(16))
    }

    public func verify(key: Data, message: Data, signature: Data) -> Bool {
        let expected = authenticate(key: key, message: message)
        guard expected.count == signature.count else { return false }
        return expected == signature
    }

    public func deriveSharedSecret(ecdh sharedPoint: Data) -> Data {
        Data(SHA256.hash(data: sharedPoint))
    }
}

/// PIN/UV Auth Protocol v2 (CTAP 2.1)
/// Uses HMAC-SHA-256 with full 32-byte output and HKDF-derived sub-keys.
public struct PINProtocolV2: PINUVAuthProtocol, Sendable {
    public let version = PINProtocolVersion.v2

    public init() {}

    public func authenticate(key: Data, message: Data) -> Data {
        let hmac = HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key))
        return Data(hmac)
    }

    public func verify(key: Data, message: Data, signature: Data) -> Bool {
        let expected = authenticate(key: key, message: message)
        guard expected.count == signature.count else { return false }
        return expected == signature
    }

    public func deriveKeys(sharedSecret: Data) -> (encKey: Data, hmacKey: Data) {
        let prk = SymmetricKey(data: sharedSecret)
        let encKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: prk,
            salt: Data(),
            info: Data("CTAP2 AES key".utf8),
            outputByteCount: 32
        )
        let hmacKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: prk,
            salt: Data(),
            info: Data("CTAP2 HMAC key".utf8),
            outputByteCount: 32
        )
        return (
            encKey.withUnsafeBytes { Data($0) },
            hmacKey.withUnsafeBytes { Data($0) }
        )
    }
}

/// Key agreement for PIN protocols. Both v1 and v2 use P-256 ECDH.
public struct PINKeyAgreement: @unchecked Sendable {
    public let privateKey: P256.KeyAgreement.PrivateKey
    public let publicKey: P256.KeyAgreement.PublicKey

    public init() {
        self.privateKey = P256.KeyAgreement.PrivateKey()
        self.publicKey = privateKey.publicKey
    }

    public var publicKeyCOSE: CBORValue {
        let raw = publicKey.rawRepresentation
        let x = raw.prefix(32)
        let y = raw.suffix(32)
        return .map([
            (.unsignedInt(1), .unsignedInt(2)),       // kty: EC2
            (.unsignedInt(3), .negativeInt(-25)),      // alg: ECDH-ES+HKDF-256
            (.negativeInt(-1), .unsignedInt(1)),       // crv: P-256
            (.negativeInt(-2), .byteString(Data(x))),  // x
            (.negativeInt(-3), .byteString(Data(y))),  // y
        ])
    }

    public func sharedSecret(with peerPublicKey: P256.KeyAgreement.PublicKey) throws -> Data {
        let shared = try privateKey.sharedSecretFromKeyAgreement(with: peerPublicKey)
        return Data(SHA256.hash(data: shared.withUnsafeBytes { Data($0) }))
    }

    public static func publicKeyFromCOSE(_ cose: CBORValue) throws -> P256.KeyAgreement.PublicKey {
        guard case .map(let pairs) = cose else { throw AuthenticatorError.invalidRequest }
        var x: Data?
        var y: Data?
        for (key, value) in pairs {
            if case .negativeInt(-2) = key, case .byteString(let data) = value { x = data }
            if case .negativeInt(-3) = key, case .byteString(let data) = value { y = data }
        }
        guard let xData = x, let yData = y, xData.count == 32, yData.count == 32 else {
            throw AuthenticatorError.invalidRequest
        }
        return try P256.KeyAgreement.PublicKey(rawRepresentation: xData + yData)
    }
}
