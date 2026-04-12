import Foundation
import Crypto

public struct AttestationBuilder {
    public init() {}

    public func buildNoneAttestation(
        authData: Data,
        clientDataHash: Data
    ) -> Data {
        let attestationObject: CBORValue = .map([
            (.textString("fmt"), .textString("none")),
            (.textString("attStmt"), .map([])),
            (.textString("authData"), .byteString(authData)),
        ])
        return CBOREncoder().encode(attestationObject)
    }

    public func buildSelfAttestation(
        authData: Data,
        clientDataHash: Data,
        keyPair: SoftwareKeyPair
    ) throws -> Data {
        var signatureBase = Data()
        signatureBase.append(authData)
        signatureBase.append(clientDataHash)

        let signature = try keyPair.sign(signatureBase)

        let algValue: CBORValue
        switch keyPair.algorithm {
        case .es256:
            algValue = .negativeInt(-7)
        case .edDSA:
            algValue = .negativeInt(-8)
        }

        let attestationObject: CBORValue = .map([
            (.textString("fmt"), .textString("packed")),
            (.textString("attStmt"), .map([
                (.textString("alg"), algValue),
                (.textString("sig"), .byteString(signature)),
            ])),
            (.textString("authData"), .byteString(authData)),
        ])

        return CBOREncoder().encode(attestationObject)
    }

    public func buildAttestedCredentialData(
        aaguid: Data,
        credentialId: Data,
        publicKeyCOSE: Data
    ) -> Data {
        var data = Data()
        data.append(aaguid.prefix(16).padded(to: 16))

        var credIdLen = UInt16(credentialId.count).bigEndian
        data.append(Data(bytes: &credIdLen, count: 2))
        data.append(credentialId)
        data.append(publicKeyCOSE)

        return data
    }
}

extension Data {
    func padded(to length: Int) -> Data {
        if count >= length { return self }
        var padded = self
        padded.append(Data(repeating: 0, count: length - count))
        return padded
    }
}
