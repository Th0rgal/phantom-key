import Testing
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import PhantomKeyCore

// MARK: - Canonical CBOR Tests

@Suite("Canonical CBOR Encoding")
struct CanonicalCBORTests {
    @Test("Canonical encoder sorts map keys by encoded length then lexicographically")
    func canonicalMapKeySorting() throws {
        let map: CBORValue = .map([
            (.textString("longer-key"), .unsignedInt(2)),
            (.textString("b"), .unsignedInt(1)),
            (.textString("a"), .unsignedInt(0)),
        ])

        let canonical = CBOREncoder(canonical: true)
        let encoded = canonical.encode(map)
        let decoded = try CBORDecoder().decode(encoded)

        guard case .map(let pairs) = decoded else {
            Issue.record("Expected map")
            return
        }

        // Short keys first (by encoded length), then lexicographic
        #expect(pairs[0].0 == .textString("a"))
        #expect(pairs[1].0 == .textString("b"))
        #expect(pairs[2].0 == .textString("longer-key"))
    }

    @Test("Canonical encoding with integer keys sorts by encoded byte length")
    func canonicalIntegerKeys() throws {
        let map: CBORValue = .map([
            (.unsignedInt(256), .bool(true)),   // encoded as 2 bytes (19 01 00)
            (.unsignedInt(1), .bool(false)),     // encoded as 1 byte (01)
            (.unsignedInt(24), .bool(true)),     // encoded as 2 bytes (18 18)
        ])

        let canonical = CBOREncoder(canonical: true)
        let encoded = canonical.encode(map)
        let decoded = try CBORDecoder().decode(encoded)

        guard case .map(let pairs) = decoded else {
            Issue.record("Expected map")
            return
        }

        #expect(pairs[0].0 == .unsignedInt(1))
        // 24 and 256 both have multi-byte encoding; 24 is shorter
        #expect(pairs[1].0 == .unsignedInt(24))
        #expect(pairs[2].0 == .unsignedInt(256))
    }

    @Test("Non-canonical encoder preserves insertion order")
    func nonCanonicalPreservesOrder() throws {
        let map: CBORValue = .map([
            (.textString("z"), .unsignedInt(0)),
            (.textString("a"), .unsignedInt(1)),
        ])

        let standard = CBOREncoder(canonical: false)
        let encoded = standard.encode(map)
        let decoded = try CBORDecoder().decode(encoded)

        guard case .map(let pairs) = decoded else {
            Issue.record("Expected map")
            return
        }

        #expect(pairs[0].0 == .textString("z"))
        #expect(pairs[1].0 == .textString("a"))
    }
}

// MARK: - PIN Protocol Tests

@Suite("PIN Protocol")
struct PINProtocolTests {
    @Test("PIN Protocol v1 authenticates with truncated HMAC")
    func v1Authenticate() {
        let v1 = PINProtocolV1()
        let key = Data(repeating: 0xAA, count: 32)
        let message = Data("test message".utf8)

        let auth = v1.authenticate(key: key, message: message)
        #expect(auth.count == 16) // truncated to 16 bytes
    }

    @Test("PIN Protocol v1 verify succeeds for correct signature")
    func v1Verify() {
        let v1 = PINProtocolV1()
        let key = Data(repeating: 0xBB, count: 32)
        let message = Data("verify me".utf8)

        let auth = v1.authenticate(key: key, message: message)
        #expect(v1.verify(key: key, message: message, signature: auth) == true)
    }

    @Test("PIN Protocol v1 verify fails for wrong message")
    func v1VerifyWrong() {
        let v1 = PINProtocolV1()
        let key = Data(repeating: 0xCC, count: 32)

        let auth = v1.authenticate(key: key, message: Data("correct".utf8))
        #expect(v1.verify(key: key, message: Data("wrong".utf8), signature: auth) == false)
    }

    @Test("PIN Protocol v2 uses full 32-byte HMAC")
    func v2Authenticate() {
        let v2 = PINProtocolV2()
        let key = Data(repeating: 0xDD, count: 32)
        let message = Data("test".utf8)

        let auth = v2.authenticate(key: key, message: message)
        #expect(auth.count == 32)
    }

    @Test("PIN Protocol v2 verify roundtrip")
    func v2VerifyRoundtrip() {
        let v2 = PINProtocolV2()
        let key = Data(repeating: 0xEE, count: 32)
        let message = Data("roundtrip".utf8)

        let auth = v2.authenticate(key: key, message: message)
        #expect(v2.verify(key: key, message: message, signature: auth) == true)
    }

    @Test("PIN Protocol v2 derives separate enc and hmac keys")
    func v2DeriveKeys() {
        let v2 = PINProtocolV2()
        let sharedSecret = Data(repeating: 0xFF, count: 32)

        let (encKey, hmacKey) = v2.deriveKeys(sharedSecret: sharedSecret)
        #expect(encKey.count == 32)
        #expect(hmacKey.count == 32)
        #expect(encKey != hmacKey)
    }

    @Test("PIN Protocol v1 shared secret derivation")
    func v1DeriveSharedSecret() {
        let v1 = PINProtocolV1()
        let point = Data(repeating: 0x42, count: 32)
        let secret = v1.deriveSharedSecret(ecdh: point)
        #expect(secret.count == 32)
    }

    @Test("PIN key agreement produces matching shared secrets")
    func keyAgreement() throws {
        let alice = PINKeyAgreement()
        let bob = PINKeyAgreement()

        let aliceSecret = try alice.sharedSecret(with: bob.publicKey)
        let bobSecret = try bob.sharedSecret(with: alice.publicKey)
        #expect(aliceSecret == bobSecret)
        #expect(aliceSecret.count == 32)
    }

    @Test("PIN key agreement COSE public key encoding")
    func cosePublicKey() throws {
        let ka = PINKeyAgreement()
        let cose = ka.publicKeyCOSE

        guard case .map(let pairs) = cose else {
            Issue.record("Expected COSE map")
            return
        }
        #expect(pairs.count == 5)
        // kty = EC2
        #expect(pairs[0] == (.unsignedInt(1), .unsignedInt(2)))
    }

    @Test("PIN key agreement parses COSE public key")
    func parseCOSE() throws {
        let ka = PINKeyAgreement()
        let cose = ka.publicKeyCOSE
        let parsed = try PINKeyAgreement.publicKeyFromCOSE(cose)
        #expect(parsed.rawRepresentation == ka.publicKey.rawRepresentation)
    }
}

// MARK: - HMAC-Secret Tests

@Suite("HMAC-Secret Extension")
struct HMACSecretTests {
    let processor = HMACSecretProcessor()

    @Test("Generate credential secret is 32 bytes")
    func generateSecret() {
        let secret = HMACSecretProcessor.generateCredentialSecret()
        #expect(secret.count == 32)
    }

    @Test("Generated secrets are unique")
    func uniqueSecrets() {
        let s1 = HMACSecretProcessor.generateCredentialSecret()
        let s2 = HMACSecretProcessor.generateCredentialSecret()
        #expect(s1 != s2)
    }

    @Test("Compute single salt output is 32 bytes")
    func singleSaltOutput() {
        let secret = Data(repeating: 0xAA, count: 32)
        let salt = Data(repeating: 0xBB, count: 32)
        let output = processor.computeOutputs(credentialSecret: secret, salt1: salt)
        #expect(output.count == 32)
    }

    @Test("Compute two salt outputs is 64 bytes")
    func twoSaltOutputs() {
        let secret = Data(repeating: 0xAA, count: 32)
        let salt1 = Data(repeating: 0xBB, count: 32)
        let salt2 = Data(repeating: 0xCC, count: 32)
        let output = processor.computeOutputs(credentialSecret: secret, salt1: salt1, salt2: salt2)
        #expect(output.count == 64)
    }

    @Test("Same inputs produce same HMAC outputs")
    func deterministic() {
        let secret = Data(repeating: 0xDD, count: 32)
        let salt = Data(repeating: 0xEE, count: 32)
        let out1 = processor.computeOutputs(credentialSecret: secret, salt1: salt)
        let out2 = processor.computeOutputs(credentialSecret: secret, salt1: salt)
        #expect(out1 == out2)
    }

    @Test("Different credentials produce different outputs")
    func differentCredentials() {
        let salt = Data(repeating: 0xFF, count: 32)
        let out1 = processor.computeOutputs(
            credentialSecret: Data(repeating: 0x01, count: 32), salt1: salt)
        let out2 = processor.computeOutputs(
            credentialSecret: Data(repeating: 0x02, count: 32), salt1: salt)
        #expect(out1 != out2)
    }

    @Test("Salt auth verification with PIN protocol v1")
    func verifySaltAuthV1() {
        let sharedSecret = Data(repeating: 0xAA, count: 32)
        let saltEnc = Data(repeating: 0xBB, count: 48)

        let key = SymmetricKey(data: sharedSecret)
        let fullHmac = Data(HMAC<SHA256>.authenticationCode(for: saltEnc, using: key))
        let saltAuth = Data(fullHmac.prefix(16))

        let valid = processor.verifySaltAuth(
            saltAuth: saltAuth, saltEnc: saltEnc,
            sharedSecret: sharedSecret, pinProtocol: .v1)
        #expect(valid == true)
    }

    @Test("Salt auth verification with PIN protocol v2")
    func verifySaltAuthV2() {
        let sharedSecret = Data(repeating: 0xCC, count: 32)
        let saltEnc = Data(repeating: 0xDD, count: 48)

        let key = SymmetricKey(data: sharedSecret)
        let saltAuth = Data(HMAC<SHA256>.authenticationCode(for: saltEnc, using: key))

        let valid = processor.verifySaltAuth(
            saltAuth: saltAuth, saltEnc: saltEnc,
            sharedSecret: sharedSecret, pinProtocol: .v2)
        #expect(valid == true)
    }

    @Test("AES-CBC encrypt/decrypt roundtrip for single salt")
    func aesCBCRoundtripSingleSalt() throws {
        let key = Data(repeating: 0xAA, count: 32)
        let iv = Data(repeating: 0x11, count: 16)
        let plaintext = Data(repeating: 0x42, count: 32) // one 32-byte salt

        let ciphertext = try aesCBCEncrypt(key: key, iv: iv, plaintext: plaintext)
        #expect(ciphertext.count == 32)
        #expect(ciphertext != plaintext)

        let decrypted = try aesCBCDecrypt(key: key, iv: iv, ciphertext: ciphertext)
        #expect(decrypted == plaintext)
    }

    @Test("AES-CBC encrypt/decrypt roundtrip for two salts")
    func aesCBCRoundtripTwoSalts() throws {
        let key = Data(repeating: 0xBB, count: 32)
        let iv = Data(repeating: 0x22, count: 16)
        var plaintext = Data(repeating: 0x01, count: 32)
        plaintext.append(Data(repeating: 0x02, count: 32))

        let ciphertext = try aesCBCEncrypt(key: key, iv: iv, plaintext: plaintext)
        #expect(ciphertext.count == 64)

        let decrypted = try aesCBCDecrypt(key: key, iv: iv, ciphertext: ciphertext)
        #expect(decrypted == plaintext)
    }

    @Test("Salt encrypt/decrypt end-to-end via HMACSecretProcessor")
    func saltEncryptDecryptEndToEnd() throws {
        let sharedSecret = Data(repeating: 0xCC, count: 32)
        let salt1 = Data(repeating: 0x11, count: 32)
        let salt2 = Data(repeating: 0x22, count: 32)

        // Encrypt salts as a platform would: IV + AES-CBC(salt1 || salt2)
        var iv = [UInt8](repeating: 0, count: 16)
        for i in 0..<16 { iv[i] = UInt8.random(in: 0...255) }
        let ivData = Data(iv)
        let plainSalts = salt1 + salt2
        let encrypted = try aesCBCEncrypt(key: sharedSecret, iv: ivData, plaintext: plainSalts)
        let saltEnc = ivData + encrypted // 16 IV + 64 ciphertext = 80 bytes

        // Decrypt via HMACSecretProcessor
        let (decSalt1, decSalt2) = try processor.decryptSalts(
            saltEnc: saltEnc, sharedSecret: sharedSecret, pinProtocol: .v1)
        #expect(decSalt1 == salt1)
        #expect(decSalt2 == salt2)
    }

    @Test("HMAC output encrypt/decrypt roundtrip")
    func hmacOutputEncryptDecrypt() throws {
        let sharedSecret = Data(repeating: 0xDD, count: 32)
        let outputs = Data(repeating: 0xAA, count: 32) // single HMAC output

        let encrypted = try processor.encryptOutputs(outputs: outputs, sharedSecret: sharedSecret)
        // encrypted = IV (16) + ciphertext (32)
        #expect(encrypted.count == 48)

        let iv = encrypted.prefix(16)
        let ciphertext = Data(encrypted.suffix(from: 16))
        let decrypted = try aesCBCDecrypt(key: sharedSecret, iv: Data(iv), ciphertext: ciphertext)
        #expect(decrypted == outputs)
    }

    @Test("AES-CBC rejects invalid key length")
    func aesCBCInvalidKeyLength() {
        let shortKey = Data(repeating: 0, count: 16)
        let iv = Data(repeating: 0, count: 16)
        let plaintext = Data(repeating: 0, count: 16)
        #expect(throws: HMACSecretError.self) {
            try aesCBCEncrypt(key: shortKey, iv: iv, plaintext: plaintext)
        }
    }

    @Test("AES-CBC rejects non-block-aligned plaintext")
    func aesCBCNonAligned() {
        let key = Data(repeating: 0, count: 32)
        let iv = Data(repeating: 0, count: 16)
        let plaintext = Data(repeating: 0, count: 15) // not a multiple of 16
        #expect(throws: HMACSecretError.self) {
            try aesCBCEncrypt(key: key, iv: iv, plaintext: plaintext)
        }
    }
}

// MARK: - Large Blob Storage Tests

@Suite("Large Blob Storage")
struct LargeBlobStorageTests {
    @Test("Initial storage has valid integrity")
    func initialIntegrity() async throws {
        let store = LargeBlobStorage()
        try await store.verifyIntegrity()
    }

    @Test("Read from initial storage returns data")
    func readInitial() async {
        let store = LargeBlobStorage()
        let data = await store.read(offset: 0, count: 100)
        #expect(data.count > 0) // empty array + hash
    }

    @Test("Initial entries list is empty")
    func emptyEntries() async throws {
        let store = LargeBlobStorage()
        let entries = try await store.entries()
        #expect(entries.isEmpty)
    }

    @Test("Set and retrieve entries")
    func setAndGetEntries() async throws {
        let store = LargeBlobStorage()
        let entry = LargeBlobEntry(
            ciphertext: Data(repeating: 0xAA, count: 32),
            nonce: Data(repeating: 0xBB, count: 12),
            origSize: 28
        )

        try await store.setEntries([entry])
        let retrieved = try await store.entries()
        #expect(retrieved.count == 1)
        #expect(retrieved[0].ciphertext == entry.ciphertext)
        #expect(retrieved[0].nonce == entry.nonce)
        #expect(retrieved[0].origSize == 28)
    }

    @Test("Storage respects max size limit")
    func maxSizeLimit() async {
        let store = LargeBlobStorage(maxSize: 100)
        let bigEntry = LargeBlobEntry(
            ciphertext: Data(repeating: 0xCC, count: 200),
            nonce: Data(repeating: 0xDD, count: 12),
            origSize: 200
        )

        do {
            try await store.setEntries([bigEntry])
            Issue.record("Expected storageFull error")
        } catch {
            #expect(error is LargeBlobError)
        }
    }

    @Test("Multiple entries roundtrip")
    func multipleEntries() async throws {
        let store = LargeBlobStorage()
        let entries = (0..<3).map { i in
            LargeBlobEntry(
                ciphertext: Data(repeating: UInt8(i), count: 16),
                nonce: Data(repeating: UInt8(i + 10), count: 12),
                origSize: 16
            )
        }

        try await store.setEntries(entries)
        let retrieved = try await store.entries()
        #expect(retrieved.count == 3)
    }
}

// MARK: - Credential Management Tests

@Suite("Credential Management")
struct CredentialManagementTests {
    /// Simple in-memory credential store for testing.
    actor TestCredentialStore: CredentialStore {
        var credentials: [StoredCredential] = []

        func store(credential: StoredCredential) async throws {
            credentials.append(credential)
        }

        func find(relyingPartyId: String, credentialId: Data?) async throws -> [StoredCredential] {
            credentials.filter { $0.relyingPartyId == relyingPartyId }
                .filter { credentialId == nil || $0.credentialId == credentialId }
        }

        func findAll(relyingPartyId: String) async throws -> [StoredCredential] {
            try await find(relyingPartyId: relyingPartyId, credentialId: nil)
        }

        func delete(credentialId: Data) async throws {
            credentials.removeAll { $0.credentialId == credentialId }
        }

        func enumerateRelyingParties() async throws -> [String] {
            Array(Set(credentials.map(\.relyingPartyId))).sorted()
        }

        func countResidentCredentials() async throws -> Int {
            credentials.filter(\.isResident).count
        }

        nonisolated func maxResidentCredentials() -> Int {
            100
        }

        func update(credentialId: Data, userName: String, userDisplayName: String) async throws {
            if let idx = credentials.firstIndex(where: { $0.credentialId == credentialId }) {
                credentials[idx].userName = userName
                credentials[idx].userDisplayName = userDisplayName
            }
        }
    }

    private func makeStore(with creds: [StoredCredential]) async -> TestCredentialStore {
        let store = TestCredentialStore()
        for cred in creds {
            try! await store.store(credential: cred)
        }
        return store
    }

    private func makeCred(rpId: String, userId: UInt8, name: String) -> StoredCredential {
        StoredCredential(
            credentialId: Data([userId]),
            relyingPartyId: rpId,
            relyingPartyName: rpId,
            userId: Data([userId]),
            userName: name,
            userDisplayName: name,
            privateKeySerialized: Data(),
            algorithm: -7,
            isResident: true
        )
    }

    @Test("Get credentials metadata")
    func getMetadata() async throws {
        let store = await makeStore(with: [
            makeCred(rpId: "a.com", userId: 1, name: "alice"),
            makeCred(rpId: "b.com", userId: 2, name: "bob"),
        ])

        let manager = CredentialManager(store: store)
        let request = CredentialManagementRequest(
            subCommand: .getCredsMetadata,
            subCommandParams: nil,
            pinUvAuthProtocol: nil,
            pinUvAuthParam: nil
        )

        let response = try await manager.handleCommand(request)
        #expect(response.existingResidentCredentialsCount == 2)
        #expect(response.maxPossibleRemainingResidentCredentialsCount == 98)
    }

    @Test("Enumerate relying parties")
    func enumerateRPs() async throws {
        let store = await makeStore(with: [
            makeCred(rpId: "github.com", userId: 1, name: "alice"),
            makeCred(rpId: "google.com", userId: 2, name: "bob"),
        ])

        let manager = CredentialManager(store: store)
        let beginReq = CredentialManagementRequest(
            subCommand: .enumerateRPsBegin, subCommandParams: nil,
            pinUvAuthProtocol: nil, pinUvAuthParam: nil
        )

        let first = try await manager.handleCommand(beginReq)
        #expect(first.totalRPs == 2)
        #expect(first.rp != nil)

        let nextReq = CredentialManagementRequest(
            subCommand: .enumerateRPsGetNextRP, subCommandParams: nil,
            pinUvAuthProtocol: nil, pinUvAuthParam: nil
        )
        let second = try await manager.handleCommand(nextReq)
        #expect(second.rp != nil)
    }

    @Test("Enumerate credentials for RP throws when empty")
    func enumerateEmptyThrows() async {
        let store = TestCredentialStore()
        let manager = CredentialManager(store: store)

        let request = CredentialManagementRequest(
            subCommand: .enumerateRPsBegin, subCommandParams: nil,
            pinUvAuthProtocol: nil, pinUvAuthParam: nil
        )

        do {
            _ = try await manager.handleCommand(request)
            Issue.record("Expected noCredentials error")
        } catch {
            #expect(error is CTAPError)
        }
    }
}

// MARK: - Noise NK Handshake Tests

@Suite("Noise NK Channel Encryption")
struct NoiseNKTests {
    @Test("Full Noise NK handshake produces working cipher states")
    func fullHandshake() throws {
        // Responder (iPhone) has a static key
        let responderStatic = Curve25519.KeyAgreement.PrivateKey()
        let responderStaticPublic = responderStatic.publicKey.rawRepresentation

        // Initiator (Mac) starts handshake
        var ss = SymmetricState(protocolName: NoiseNK.protocolName)
        ss.mixHash(responderStaticPublic)

        let e = Curve25519.KeyAgreement.PrivateKey()
        ss.mixHash(e.publicKey.rawRepresentation)
        let rs = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: responderStaticPublic)
        let sharedES = try e.sharedSecretFromKeyAgreement(with: rs)
        ss.mixKey(sharedES.withUnsafeBytes { Data($0) })

        let message1 = e.publicKey.rawRepresentation

        // Responder processes message1
        let (response, responderSend, responderRecv) = try NoiseNK.responder(
            staticPrivateKey: responderStatic,
            message: Data(message1)
        )

        // Initiator finalizes
        var (initiatorSend, initiatorRecv) = try NoiseNK.initiatorFinalize(
            pendingEphemeralPrivate: e,
            symmetricState: &ss,
            responseMessage: response
        )

        // Initiator sends, responder receives
        var rRecv = responderRecv
        let ciphertext = try initiatorSend.encrypt(Data("hello from mac".utf8))
        let plaintext = try rRecv.decrypt(ciphertext)
        #expect(plaintext == Data("hello from mac".utf8))

        // Responder sends, initiator receives
        var rSend = responderSend
        let ciphertext2 = try rSend.encrypt(Data("hello from iphone".utf8))
        let plaintext2 = try initiatorRecv.decrypt(ciphertext2)
        #expect(plaintext2 == Data("hello from iphone".utf8))
    }

    @Test("Responder rejects short handshake message")
    func rejectShortMessage() {
        let key = Curve25519.KeyAgreement.PrivateKey()
        #expect(throws: NoiseError.self) {
            try NoiseNK.responder(staticPrivateKey: key, message: Data(repeating: 0, count: 10))
        }
    }

    @Test("CipherState counter-based nonces increment")
    func nonceIncrement() throws {
        let key = SymmetricKey(data: Data(repeating: 0xAA, count: 32))
        var cipher = CipherState(key: key)

        #expect(cipher.currentNonce == 0)
        _ = try cipher.encrypt(Data("msg1".utf8))
        #expect(cipher.currentNonce == 1)
        _ = try cipher.encrypt(Data("msg2".utf8))
        #expect(cipher.currentNonce == 2)
    }

    @Test("CipherState encrypt/decrypt roundtrip")
    func cipherRoundtrip() throws {
        let key = SymmetricKey(data: Data(repeating: 0xBB, count: 32))
        var encryptor = CipherState(key: key)
        var decryptor = CipherState(key: key)

        let messages = ["hello", "world", "fido2", "ctap2.1"]
        for msg in messages {
            let ct = try encryptor.encrypt(Data(msg.utf8))
            let pt = try decryptor.decrypt(ct)
            #expect(pt == Data(msg.utf8))
        }
    }

    @Test("CipherState with associated data")
    func cipherWithAD() throws {
        let key = SymmetricKey(data: Data(repeating: 0xCC, count: 32))
        var enc = CipherState(key: key)
        var dec = CipherState(key: key)

        let ad = Data("associated".utf8)
        let ct = try enc.encrypt(Data("secret".utf8), associatedData: ad)
        let pt = try dec.decrypt(ct, associatedData: ad)
        #expect(pt == Data("secret".utf8))
    }

    @Test("CipherState wrong AD fails decryption")
    func wrongADFails() throws {
        let key = SymmetricKey(data: Data(repeating: 0xDD, count: 32))
        var enc = CipherState(key: key)
        var dec = CipherState(key: key)

        let ct = try enc.encrypt(Data("secret".utf8), associatedData: Data("correct-ad".utf8))
        #expect(throws: Error.self) {
            try dec.decrypt(ct, associatedData: Data("wrong-ad".utf8))
        }
    }

    @Test("CipherState rejects too-short data")
    func rejectShortCiphertext() throws {
        let key = SymmetricKey(data: Data(repeating: 0xEE, count: 32))
        var dec = CipherState(key: key)

        #expect(throws: NoiseError.self) {
            try dec.decrypt(Data(repeating: 0, count: 10))
        }
    }

    @Test("Key ratcheting occurs at interval")
    func keyRatcheting() throws {
        let key = SymmetricKey(data: Data(repeating: 0xFF, count: 32))
        // Set ratchet interval to 3 for testing
        var enc = CipherState(key: key, nonce: 0, ratchetInterval: 3)
        var dec = CipherState(key: key, nonce: 0, ratchetInterval: 3)

        // Messages 0, 1, 2 should work; after message 2 (nonce becomes 3), ratchet happens
        for i in 0..<6 {
            let ct = try enc.encrypt(Data("msg\(i)".utf8))
            let pt = try dec.decrypt(ct)
            #expect(pt == Data("msg\(i)".utf8))
        }
    }
}

// MARK: - CTAP 2.1 Status Codes Tests

@Suite("CTAP 2.1 Status Codes")
struct CTAP21StatusCodeTests {
    @Test("New CTAP 2.1 status codes have correct values")
    func newStatusCodes() {
        #expect(CTAPStatusCode.pinInvalid.rawValue == 0x31)
        #expect(CTAPStatusCode.pinBlocked.rawValue == 0x32)
        #expect(CTAPStatusCode.pinAuthInvalid.rawValue == 0x33)
        #expect(CTAPStatusCode.uvBlocked.rawValue == 0x3C)
        #expect(CTAPStatusCode.integrityFailure.rawValue == 0x3D)
        #expect(CTAPStatusCode.invalidSubcommand.rawValue == 0x3E)
        #expect(CTAPStatusCode.largeBlobStorageFull.rawValue == 0x42)
    }

    @Test("Credential protection levels")
    func credProtectLevels() {
        #expect(CredentialProtectionLevel.userVerificationOptional.rawValue == 1)
        #expect(CredentialProtectionLevel.userVerificationOptionalWithCredentialIDList.rawValue == 2)
        #expect(CredentialProtectionLevel.userVerificationRequired.rawValue == 3)
    }

    @Test("Credential management sub-commands")
    func credMgmtSubcommands() {
        #expect(CredentialManagementSubCommand.getCredsMetadata.rawValue == 0x01)
        #expect(CredentialManagementSubCommand.enumerateRPsBegin.rawValue == 0x02)
        #expect(CredentialManagementSubCommand.deleteCredential.rawValue == 0x06)
        #expect(CredentialManagementSubCommand.updateUserInformation.rawValue == 0x07)
    }
}

// MARK: - AuthenticatorInfo CTAP 2.1 Tests

@Suite("AuthenticatorInfo CTAP 2.1")
struct AuthenticatorInfoCTAP21Tests {
    @Test("PhantomKey reports FIDO_2_1")
    func fido21Version() {
        let info = AuthenticatorInfo.phantomKey
        #expect(info.versions.contains("FIDO_2_1"))
        #expect(info.versions.contains("FIDO_2_0"))
    }

    @Test("PhantomKey reports CTAP 2.1 extensions")
    func extensions() {
        let info = AuthenticatorInfo.phantomKey
        #expect(info.extensions.contains("credProtect"))
        #expect(info.extensions.contains("hmac-secret"))
        #expect(info.extensions.contains("largeBlobKey"))
    }

    @Test("PhantomKey reports PIN protocols v2 and v1")
    func pinProtocols() {
        let info = AuthenticatorInfo.phantomKey
        #expect(info.pinProtocols == [2, 1])
    }

    @Test("PhantomKey reports credMgmt and largeBlobs options")
    func options() {
        let info = AuthenticatorInfo.phantomKey
        #expect(info.options["credMgmt"] == true)
        #expect(info.options["largeBlobs"] == true)
        #expect(info.options["alwaysUv"] == true)
    }

    @Test("AuthenticatorInfo toCBOR includes extensions key")
    func toCBORExtensions() throws {
        let info = AuthenticatorInfo.phantomKey
        let cbor = info.toCBOR()

        guard case .map(let pairs) = cbor else {
            Issue.record("Expected map")
            return
        }

        // Key 0x02 should be extensions
        let extensionsPair = pairs.first { pair in
            if case .unsignedInt(0x02) = pair.0 { return true }
            return false
        }
        #expect(extensionsPair != nil)
        if case .array(let exts) = extensionsPair?.1 {
            #expect(exts.contains(.textString("hmac-secret")))
        }
    }

    @Test("AuthenticatorInfo toCBOR includes maxSerializedLargeBlobArray")
    func toCBORLargeBlob() throws {
        let info = AuthenticatorInfo.phantomKey
        let cbor = info.toCBOR()

        guard case .map(let pairs) = cbor else {
            Issue.record("Expected map")
            return
        }

        let blobPair = pairs.first { pair in
            if case .unsignedInt(0x0B) = pair.0 { return true }
            return false
        }
        #expect(blobPair != nil)
        if case .unsignedInt(let val) = blobPair?.1 {
            #expect(val == 4096)
        }
    }
}

// MARK: - New Envelope Message Types Tests

@Suite("CTAP 2.1 Message Types")
struct CTAP21MessageTypeTests {
    @Test("Credential management message types exist")
    func credMgmtTypes() {
        #expect(MessageType.credentialManagementRequest.rawValue == 0x16)
        #expect(MessageType.credentialManagementResponse.rawValue == 0x17)
    }

    @Test("Large blob message types exist")
    func largeBlobTypes() {
        #expect(MessageType.largeBlobRequest.rawValue == 0x18)
        #expect(MessageType.largeBlobResponse.rawValue == 0x19)
    }

    @Test("Noise handshake message types exist")
    func noiseTypes() {
        #expect(MessageType.noiseHandshakeInit.rawValue == 0x04)
        #expect(MessageType.noiseHandshakeResponse.rawValue == 0x05)
    }

    @Test("All message types still have unique raw values")
    func uniqueMessageTypes() {
        let types: [MessageType] = [
            .pairingRequest, .pairingResponse, .pairingConfirm,
            .noiseHandshakeInit, .noiseHandshakeResponse,
            .makeCredentialRequest, .makeCredentialResponse,
            .getAssertionRequest, .getAssertionResponse,
            .getInfoRequest, .getInfoResponse,
            .credentialManagementRequest, .credentialManagementResponse,
            .largeBlobRequest, .largeBlobResponse,
            .policyUpdate, .policyResponse,
            .keepAlive, .cancel, .error,
        ]
        let rawValues = types.map(\.rawValue)
        #expect(Set(rawValues).count == rawValues.count)
    }

    @Test("New message types serialize in envelopes")
    func newTypesInEnvelope() throws {
        for msgType in [MessageType.credentialManagementRequest,
                        .credentialManagementResponse,
                        .largeBlobRequest,
                        .largeBlobResponse,
                        .noiseHandshakeInit,
                        .noiseHandshakeResponse] {
            let envelope = Envelope(type: msgType, sequence: 1, payload: Data([0x42]))
            let serialized = envelope.serialize()
            let deserialized = try Envelope.deserialize(serialized)
            #expect(deserialized.type == msgType)
        }
    }
}

// MARK: - Pairing Protocol with Noise Tests

@Suite("Pairing Protocol Noise Integration")
struct PairingNoiseTests {
    @Test("PairingResponder can process Noise handshake")
    func responderNoiseHandshake() throws {
        let responder = PairingResponder()

        // Simulate initiator's ephemeral key
        let initiatorEphemeral = Curve25519.KeyAgreement.PrivateKey()
        let message = initiatorEphemeral.publicKey.rawRepresentation

        let (response, sendCipher, receiveCipher) = try responder.processNoiseHandshake(message: Data(message))
        #expect(response.count == 32)
        #expect(sendCipher.currentNonce == 0)
        #expect(receiveCipher.currentNonce == 0)
    }

    @Test("PairingInitiator and PairingResponder derive compatible keys")
    func initiatorResponderCompatibility() throws {
        let initiator = PairingInitiator()
        let responder = PairingResponder()

        let qrData = initiator.qrData
        let deviceId = "test"

        // Legacy pairing still works
        let iPaired = try initiator.completePairing(
            remotePublicKey: responder.publicKeyData,
            deviceId: deviceId,
            deviceName: "iPhone"
        )
        let rPaired = try responder.completePairing(scannedData: qrData, deviceId: "mac")
        #expect(iPaired.sharedSecret == rPaired.sharedSecret)
    }
}

// MARK: - Stored Credential CTAP 2.1 Fields Tests

@Suite("StoredCredential CTAP 2.1 Fields")
struct StoredCredentialCTAP21Tests {
    @Test("StoredCredential includes credProtect field")
    func credProtect() {
        let cred = StoredCredential(
            credentialId: Data([0x01]),
            relyingPartyId: "test.com",
            relyingPartyName: "Test",
            userId: Data([0x0A]),
            userName: "alice",
            userDisplayName: "Alice",
            privateKeySerialized: Data(),
            algorithm: -7,
            credProtect: 2
        )
        #expect(cred.credProtect == 2)
    }

    @Test("StoredCredential includes largeBlobKey field")
    func largeBlobKey() {
        let key = Data(repeating: 0xBB, count: 32)
        let cred = StoredCredential(
            credentialId: Data([0x02]),
            relyingPartyId: "test.com",
            relyingPartyName: "Test",
            userId: Data([0x0B]),
            userName: "bob",
            userDisplayName: "Bob",
            privateKeySerialized: Data(),
            algorithm: -7,
            largeBlobKey: key
        )
        #expect(cred.largeBlobKey == key)
    }

    @Test("StoredCredential includes hmacSecret field")
    func hmacSecret() {
        let secret = Data(repeating: 0xCC, count: 32)
        let cred = StoredCredential(
            credentialId: Data([0x03]),
            relyingPartyId: "test.com",
            relyingPartyName: "Test",
            userId: Data([0x0C]),
            userName: "charlie",
            userDisplayName: "Charlie",
            privateKeySerialized: Data(),
            algorithm: -7,
            hmacSecret: secret
        )
        #expect(cred.hmacSecret == secret)
    }

    @Test("StoredCredential CTAP 2.1 fields are Codable")
    func codableWithNewFields() throws {
        let cred = StoredCredential(
            credentialId: Data([0x01, 0x02]),
            relyingPartyId: "example.com",
            relyingPartyName: "Example",
            userId: Data([0x0A]),
            userName: "alice",
            userDisplayName: "Alice",
            privateKeySerialized: Data(repeating: 0xAA, count: 32),
            algorithm: -7,
            isResident: true,
            signatureCounter: 5,
            credProtect: 3,
            largeBlobKey: Data(repeating: 0xBB, count: 32),
            hmacSecret: Data(repeating: 0xCC, count: 32)
        )

        let data = try JSONEncoder().encode(cred)
        let decoded = try JSONDecoder().decode(StoredCredential.self, from: data)
        #expect(decoded.credProtect == 3)
        #expect(decoded.largeBlobKey?.count == 32)
        #expect(decoded.hmacSecret?.count == 32)
    }

    @Test("StoredCredential mutable userName and userDisplayName")
    func mutableUserInfo() {
        var cred = StoredCredential(
            credentialId: Data([0x01]),
            relyingPartyId: "test.com",
            relyingPartyName: "Test",
            userId: Data([0x0A]),
            userName: "old",
            userDisplayName: "Old Name",
            privateKeySerialized: Data(),
            algorithm: -7
        )

        cred.userName = "new"
        cred.userDisplayName = "New Name"
        #expect(cred.userName == "new")
        #expect(cred.userDisplayName == "New Name")
    }
}

// MARK: - AuthenticatorData Extensions Tests

@Suite("AuthenticatorData Extensions")
struct AuthenticatorDataExtensionTests {
    @Test("Serialize with extensions data")
    func serializeWithExtensions() {
        let rpIdHash = AuthenticatorData.makeRpIdHash("example.com")
        let flags = AuthenticatorData.flagUserPresent | AuthenticatorData.flagExtensionData
        let extData = Data([0x01, 0x02, 0x03])

        let authData = AuthenticatorData(
            rpIdHash: rpIdHash,
            flags: flags,
            signCount: 1,
            extensions: extData
        )

        let serialized = authData.serialize()
        #expect(serialized.count == 37 + 3) // base + extensions
        #expect(serialized[32] & AuthenticatorData.flagExtensionData != 0)
    }

    @Test("Extension data flag constant")
    func extensionDataFlag() {
        #expect(AuthenticatorData.flagExtensionData == 0x80)
    }
}
