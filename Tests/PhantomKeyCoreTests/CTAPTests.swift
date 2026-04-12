import Testing
import Foundation
@testable import PhantomKeyCore

@Suite("CTAP Commands")
struct CTAPCommandTests {
    @Test("MakeCredentialRequest stores all fields")
    func makeCredentialRequest() {
        let clientDataHash = Data(repeating: 0xAA, count: 32)
        let rp = RelyingParty(id: "example.com", name: "Example")
        let user = PublicKeyUser(id: Data([0x01]), name: "alice", displayName: "Alice")

        let request = MakeCredentialRequest(
            clientDataHash: clientDataHash,
            relyingParty: rp,
            user: user,
            pubKeyCredParams: [.es256],
            requireResidentKey: true,
            requireUserVerification: true
        )

        #expect(request.clientDataHash == clientDataHash)
        #expect(request.relyingParty.id == "example.com")
        #expect(request.user.name == "alice")
        #expect(request.pubKeyCredParams.count == 1)
        #expect(request.requireResidentKey == true)
    }

    @Test("GetAssertionRequest stores all fields")
    func getAssertionRequest() {
        let request = GetAssertionRequest(
            relyingPartyId: "github.com",
            clientDataHash: Data(repeating: 0xBB, count: 32),
            requireUserVerification: true
        )

        #expect(request.relyingPartyId == "github.com")
        #expect(request.clientDataHash.count == 32)
        #expect(request.allowList.isEmpty)
        #expect(request.requireUserVerification == true)
    }

    @Test("PublicKeyCredParam ES256 constant")
    func es256Constant() {
        #expect(PublicKeyCredParam.es256.algorithm == -7)
        #expect(PublicKeyCredParam.es256.type == "public-key")
    }

    @Test("PublicKeyCredParam EdDSA constant")
    func edDSAConstant() {
        #expect(PublicKeyCredParam.edDSA.algorithm == -8)
        #expect(PublicKeyCredParam.edDSA.type == "public-key")
    }

    @Test("CTAP status codes have correct raw values")
    func statusCodes() {
        #expect(CTAPStatusCode.ok.rawValue == 0x00)
        #expect(CTAPStatusCode.operationDenied.rawValue == 0x27)
        #expect(CTAPStatusCode.noCredentials.rawValue == 0x2E)
        #expect(CTAPStatusCode.notAllowed.rawValue == 0x30)
    }

    @Test("RelyingParty is Codable")
    func rpCodable() throws {
        let rp = RelyingParty(id: "test.com", name: "Test Site")
        let data = try JSONEncoder().encode(rp)
        let decoded = try JSONDecoder().decode(RelyingParty.self, from: data)
        #expect(decoded.id == rp.id)
        #expect(decoded.name == rp.name)
    }
}

@Suite("Authenticator Data")
struct AuthenticatorDataTests {
    @Test("Serialize authenticator data without attested credential")
    func serializeBasic() {
        let rpIdHash = AuthenticatorData.makeRpIdHash("example.com")
        let flags = AuthenticatorData.flagUserPresent | AuthenticatorData.flagUserVerified
        let authData = AuthenticatorData(rpIdHash: rpIdHash, flags: flags, signCount: 1)

        let serialized = authData.serialize()
        #expect(serialized.count == 37) // 32 hash + 1 flags + 4 counter
        #expect(serialized[32] == flags)
    }

    @Test("RP ID hash is SHA-256")
    func rpIdHash() {
        let hash = AuthenticatorData.makeRpIdHash("example.com")
        #expect(hash.count == 32)

        let hash2 = AuthenticatorData.makeRpIdHash("example.com")
        #expect(hash == hash2)

        let hash3 = AuthenticatorData.makeRpIdHash("other.com")
        #expect(hash != hash3)
    }

    @Test("Serialize with attested credential data")
    func serializeWithAttested() {
        let rpIdHash = AuthenticatorData.makeRpIdHash("example.com")
        let flags = AuthenticatorData.flagUserPresent | AuthenticatorData.flagAttestedCredential
        let attested = Data(repeating: 0xCC, count: 50)

        let authData = AuthenticatorData(
            rpIdHash: rpIdHash,
            flags: flags,
            signCount: 5,
            attestedCredentialData: attested
        )

        let serialized = authData.serialize()
        #expect(serialized.count == 37 + 50)
    }

    @Test("Sign counter is big-endian")
    func signCounterEndianness() {
        let rpIdHash = Data(repeating: 0, count: 32)
        let authData = AuthenticatorData(rpIdHash: rpIdHash, flags: 0x01, signCount: 0x01020304)

        let serialized = authData.serialize()
        // Counter starts at offset 33
        #expect(serialized[33] == 0x01)
        #expect(serialized[34] == 0x02)
        #expect(serialized[35] == 0x03)
        #expect(serialized[36] == 0x04)
    }
}

@Suite("Attestation")
struct AttestationTests {
    @Test("Build none attestation")
    func noneAttestation() throws {
        let builder = AttestationBuilder()
        let authData = Data(repeating: 0xAA, count: 37)
        let clientDataHash = Data(repeating: 0xBB, count: 32)

        let attestation = builder.buildNoneAttestation(
            authData: authData,
            clientDataHash: clientDataHash
        )

        let decoder = CBORDecoder()
        let decoded = try decoder.decode(attestation)

        if case .map(let pairs) = decoded {
            #expect(pairs.count == 3)
            #expect(pairs[0].0 == .textString("fmt"))
            #expect(pairs[0].1 == .textString("none"))
        } else {
            Issue.record("Expected map")
        }
    }

    @Test("Build self attestation with ES256")
    func selfAttestation() throws {
        let builder = AttestationBuilder()
        let keyPair = SoftwareKeyPair.generate(algorithm: .es256)
        let authData = Data(repeating: 0xAA, count: 37)
        let clientDataHash = Data(repeating: 0xBB, count: 32)

        let attestation = try builder.buildSelfAttestation(
            authData: authData,
            clientDataHash: clientDataHash,
            keyPair: keyPair
        )

        let decoder = CBORDecoder()
        let decoded = try decoder.decode(attestation)

        if case .map(let pairs) = decoded {
            #expect(pairs[0].1 == .textString("packed"))
            if case .map(let attStmt) = pairs[1].1 {
                #expect(attStmt.count == 2) // alg + sig
            }
        } else {
            Issue.record("Expected map")
        }
    }

    @Test("Attested credential data format")
    func attestedCredentialData() {
        let builder = AttestationBuilder()
        let aaguid = Data(repeating: 0xFF, count: 16)
        let credId = Data(repeating: 0xAA, count: 32)
        let pubKey = Data(repeating: 0xBB, count: 77)

        let data = builder.buildAttestedCredentialData(
            aaguid: aaguid,
            credentialId: credId,
            publicKeyCOSE: pubKey
        )

        // 16 AAGUID + 2 credId length + 32 credId + 77 pubKey
        #expect(data.count == 127)
        #expect(Data(data.prefix(16)) == aaguid)
        #expect(data[16] == 0x00) // credId length high byte
        #expect(data[17] == 0x20) // credId length low byte (32)
    }
}

@Suite("Stored Credential")
struct StoredCredentialTests {
    @Test("StoredCredential is Codable")
    func codableRoundtrip() throws {
        let cred = StoredCredential(
            credentialId: Data([0x01, 0x02, 0x03]),
            relyingPartyId: "github.com",
            relyingPartyName: "GitHub",
            userId: Data([0x0A]),
            userName: "alice",
            userDisplayName: "Alice",
            privateKeySerialized: Data(repeating: 0xAA, count: 32),
            algorithm: -7,
            isResident: true,
            signatureCounter: 42
        )

        let data = try JSONEncoder().encode(cred)
        let decoded = try JSONDecoder().decode(StoredCredential.self, from: data)
        #expect(decoded.relyingPartyId == "github.com")
        #expect(decoded.userName == "alice")
        #expect(decoded.signatureCounter == 42)
        #expect(decoded.isResident == true)
    }
}
