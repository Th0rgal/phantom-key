import Foundation
import Crypto

public enum KeyAlgorithm: Int, Sendable, Codable {
    case es256 = -7
    case edDSA = -8
}

public struct SoftwareKeyPair: Sendable {
    public let algorithm: KeyAlgorithm
    public let privateKeyData: Data
    public let publicKeyData: Data
    public let credentialId: Data

    public static func generate(algorithm: KeyAlgorithm) -> SoftwareKeyPair {
        switch algorithm {
        case .es256:
            let key = P256.Signing.PrivateKey()
            let credId = generateCredentialId()
            return SoftwareKeyPair(
                algorithm: .es256,
                privateKeyData: key.rawRepresentation,
                publicKeyData: key.publicKey.rawRepresentation,
                credentialId: credId
            )
        case .edDSA:
            let key = Curve25519.Signing.PrivateKey()
            let credId = generateCredentialId()
            return SoftwareKeyPair(
                algorithm: .edDSA,
                privateKeyData: key.rawRepresentation,
                publicKeyData: key.publicKey.rawRepresentation,
                credentialId: credId
            )
        }
    }

    public func sign(_ data: Data) throws -> Data {
        switch algorithm {
        case .es256:
            let key = try P256.Signing.PrivateKey(rawRepresentation: privateKeyData)
            let signature = try key.signature(for: data)
            return signature.derRepresentation
        case .edDSA:
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyData)
            return try key.signature(for: data)
        }
    }

    public func publicKeyCOSE() -> CBORValue {
        switch algorithm {
        case .es256:
            let x = publicKeyData.prefix(32)
            let y = publicKeyData.suffix(32)
            return .map([
                (.unsignedInt(1), .unsignedInt(2)),           // kty: EC2
                (.unsignedInt(3), .negativeInt(-7)),           // alg: ES256
                (.negativeInt(-1), .unsignedInt(1)),           // crv: P-256
                (.negativeInt(-2), .byteString(Data(x))),     // x
                (.negativeInt(-3), .byteString(Data(y))),     // y
            ])
        case .edDSA:
            return .map([
                (.unsignedInt(1), .unsignedInt(1)),           // kty: OKP
                (.unsignedInt(3), .negativeInt(-8)),           // alg: EdDSA
                (.negativeInt(-1), .unsignedInt(6)),           // crv: Ed25519
                (.negativeInt(-2), .byteString(publicKeyData)), // x
            ])
        }
    }

    private static func generateCredentialId() -> Data {
        var bytes = Data(count: 32)
        for i in 0..<32 {
            bytes[i] = UInt8.random(in: 0...255)
        }
        return bytes
    }
}

public struct COSEPublicKey {
    public static func encode(algorithm: KeyAlgorithm, publicKey: Data) -> Data {
        let keyPair = SoftwareKeyPair(
            algorithm: algorithm,
            privateKeyData: Data(),
            publicKeyData: publicKey,
            credentialId: Data()
        )
        let cbor = keyPair.publicKeyCOSE()
        return CBOREncoder().encode(cbor)
    }
}
