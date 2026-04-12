import Testing
import Foundation
@testable import PhantomKeyCore

@Suite("Cryptography")
struct CryptoTests {
    @Test("Generate ES256 key pair")
    func generateES256() throws {
        let kp = SoftwareKeyPair.generate(algorithm: .es256)
        #expect(kp.algorithm == .es256)
        #expect(kp.privateKeyData.count == 32)
        #expect(kp.publicKeyData.count == 64) // raw P-256 uncompressed x||y
        #expect(kp.credentialId.count == 32)
    }

    @Test("Generate EdDSA key pair")
    func generateEdDSA() throws {
        let kp = SoftwareKeyPair.generate(algorithm: .edDSA)
        #expect(kp.algorithm == .edDSA)
        #expect(kp.privateKeyData.count == 32)
        #expect(kp.publicKeyData.count == 32)
        #expect(kp.credentialId.count == 32)
    }

    @Test("ES256 sign and verify")
    func es256SignVerify() throws {
        let kp = SoftwareKeyPair.generate(algorithm: .es256)
        let message = Data("test message for signing".utf8)
        let signature = try kp.sign(message)
        #expect(signature.count > 0)
        #expect(signature.count <= 72) // DER-encoded ECDSA
    }

    @Test("EdDSA sign and verify")
    func edDSASignVerify() throws {
        let kp = SoftwareKeyPair.generate(algorithm: .edDSA)
        let message = Data("test message for signing".utf8)
        let signature = try kp.sign(message)
        #expect(signature.count == 64)
    }

    @Test("Different messages produce different signatures")
    func differentSignatures() throws {
        let kp = SoftwareKeyPair.generate(algorithm: .es256)
        let sig1 = try kp.sign(Data("message one".utf8))
        let sig2 = try kp.sign(Data("message two".utf8))
        #expect(sig1 != sig2)
    }

    @Test("COSE public key encoding for ES256")
    func coseES256() throws {
        let kp = SoftwareKeyPair.generate(algorithm: .es256)
        let cbor = kp.publicKeyCOSE()

        if case .map(let pairs) = cbor {
            #expect(pairs.count == 5)
            // kty: EC2
            #expect(pairs[0] == (.unsignedInt(1), .unsignedInt(2)))
            // alg: ES256 (-7)
            #expect(pairs[1] == (.unsignedInt(3), .negativeInt(-7)))
        } else {
            Issue.record("Expected COSE map")
        }
    }

    @Test("COSE public key encoding for EdDSA")
    func coseEdDSA() throws {
        let kp = SoftwareKeyPair.generate(algorithm: .edDSA)
        let cbor = kp.publicKeyCOSE()

        if case .map(let pairs) = cbor {
            #expect(pairs.count == 4)
            #expect(pairs[0] == (.unsignedInt(1), .unsignedInt(1))) // kty: OKP
            #expect(pairs[1] == (.unsignedInt(3), .negativeInt(-8))) // alg: EdDSA
        } else {
            Issue.record("Expected COSE map")
        }
    }

    @Test("Key exchange produces shared secret")
    func keyExchange() throws {
        let alice = PairingKeys()
        let bob = PairingKeys()

        let aliceSecret = try alice.deriveSharedSecret(remotePublicKey: bob.publicKeyData)
        let bobSecret = try bob.deriveSharedSecret(remotePublicKey: alice.publicKeyData)

        let aliceData = aliceSecret.withUnsafeBytes { Data($0) }
        let bobData = bobSecret.withUnsafeBytes { Data($0) }
        #expect(aliceData == bobData)
    }

    @Test("Channel encrypt/decrypt roundtrip")
    func channelEncryptDecrypt() throws {
        let alice = PairingKeys()
        let bob = PairingKeys()
        let sharedKey = try alice.deriveSharedSecret(remotePublicKey: bob.publicKeyData)

        let encryptor = ChannelEncryptor(sharedKey: sharedKey)
        let plaintext = Data("Hello, PhantomKey!".utf8)

        let ciphertext = try encryptor.encrypt(plaintext)
        #expect(ciphertext != plaintext)
        #expect(ciphertext.count > plaintext.count) // nonce + tag overhead

        let decrypted = try encryptor.decrypt(ciphertext)
        #expect(decrypted == plaintext)
    }

    @Test("Decrypt with wrong key fails")
    func wrongKeyDecrypt() throws {
        let alice = PairingKeys()
        let bob = PairingKeys()
        let eve = PairingKeys()

        let aliceKey = try alice.deriveSharedSecret(remotePublicKey: bob.publicKeyData)
        let eveKey = try eve.deriveSharedSecret(remotePublicKey: bob.publicKeyData)

        let encryptor = ChannelEncryptor(sharedKey: aliceKey)
        let eveDecryptor = ChannelEncryptor(sharedKey: eveKey)

        let ciphertext = try encryptor.encrypt(Data("secret".utf8))
        #expect(throws: Error.self) {
            try eveDecryptor.decrypt(ciphertext)
        }
    }

    @Test("Pairing code is 6 digits")
    func pairingCode() {
        let code = PairingKeys.generatePairingCode()
        #expect(code.count == 6)
        #expect(code.allSatisfy { $0.isNumber })
    }
}
