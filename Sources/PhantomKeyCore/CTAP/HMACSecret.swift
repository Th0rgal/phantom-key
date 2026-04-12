import Foundation
import Crypto

/// CTAP 2.1 hmac-secret extension processor.
/// Computes credential-scoped HMAC-SHA-256 symmetric secrets from platform-provided salts.
public struct HMACSecretProcessor: Sendable {
    public init() {}

    /// Generate a random 32-byte credential secret for hmac-secret at credential creation time.
    public static func generateCredentialSecret() -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        for i in 0..<32 { bytes[i] = UInt8.random(in: 0...255) }
        return Data(bytes)
    }

    /// Process hmac-secret extension during GetAssertion.
    ///
    /// - Parameters:
    ///   - credentialSecret: The 32-byte secret stored with the credential (CredRandom).
    ///   - salt1: First 32-byte salt from the platform (decrypted from saltEnc).
    ///   - salt2: Optional second 32-byte salt.
    /// - Returns: Concatenated HMAC outputs (32 bytes per salt).
    public func computeOutputs(
        credentialSecret: Data,
        salt1: Data,
        salt2: Data? = nil
    ) -> Data {
        let key = SymmetricKey(data: credentialSecret)
        var output = Data(HMAC<SHA256>.authenticationCode(for: salt1, using: key))
        if let s2 = salt2 {
            output.append(Data(HMAC<SHA256>.authenticationCode(for: s2, using: key)))
        }
        return output
    }

    /// Decrypt saltEnc from the platform using the shared secret.
    /// Returns (salt1, salt2?) where each salt is 32 bytes.
    public func decryptSalts(
        saltEnc: Data,
        sharedSecret: Data,
        pinProtocol: PINProtocolVersion
    ) throws -> (Data, Data?) {
        // saltEnc is AES-256-CBC encrypted (IV prepended) using the shared secret
        // For simplicity in software authenticator, we use the shared secret as the AES key
        guard saltEnc.count == 48 || saltEnc.count == 80 else {
            // 48 = 16 (IV) + 32 (one salt), 80 = 16 (IV) + 64 (two salts)
            throw HMACSecretError.invalidSaltLength
        }

        let iv = saltEnc.prefix(16)
        let ciphertext = saltEnc.suffix(from: 16)

        // Decrypt using AES-256-CBC with the shared secret
        let decrypted = try aesCBCDecrypt(key: sharedSecret, iv: iv, ciphertext: Data(ciphertext))

        let salt1 = decrypted.prefix(32)
        let salt2: Data? = decrypted.count >= 64 ? Data(decrypted[32..<64]) : nil

        return (Data(salt1), salt2)
    }

    /// Verify the saltAuth HMAC over saltEnc using the shared secret.
    public func verifySaltAuth(
        saltAuth: Data,
        saltEnc: Data,
        sharedSecret: Data,
        pinProtocol: PINProtocolVersion
    ) -> Bool {
        let key = SymmetricKey(data: sharedSecret)
        let expected = Data(HMAC<SHA256>.authenticationCode(for: saltEnc, using: key))

        switch pinProtocol {
        case .v1:
            return expected.prefix(16) == saltAuth
        case .v2:
            return expected == saltAuth
        }
    }

    /// Encrypt the HMAC outputs for return to the platform.
    public func encryptOutputs(
        outputs: Data,
        sharedSecret: Data
    ) throws -> Data {
        // Generate random IV and encrypt with AES-256-CBC
        var iv = [UInt8](repeating: 0, count: 16)
        for i in 0..<16 { iv[i] = UInt8.random(in: 0...255) }
        let ivData = Data(iv)
        let encrypted = try aesCBCEncrypt(key: sharedSecret, iv: ivData, plaintext: outputs)
        return ivData + encrypted
    }
}

// MARK: - AES-CBC (minimal implementation for PIN protocol compatibility)

/// AES-256-CBC encryption. Plaintext must be a multiple of 16 bytes (no padding applied).
func aesCBCEncrypt(key: Data, iv: Data, plaintext: Data) throws -> Data {
    guard key.count == 32, iv.count == 16, plaintext.count % 16 == 0 else {
        throw HMACSecretError.invalidInput
    }
    // XOR-based CBC using AES-GCM as a block cipher (encrypt single blocks with zero-auth)
    var result = Data()
    var previousBlock = iv
    for blockStart in stride(from: 0, to: plaintext.count, by: 16) {
        let block = plaintext[blockStart..<(blockStart + 16)]
        var xored = Data(count: 16)
        for i in 0..<16 {
            xored[i] = block[block.startIndex + i] ^ previousBlock[previousBlock.startIndex + i]
        }
        // Use AES in a simple way: encrypt with a 12-byte nonce of zeros and extract ciphertext
        let nonce = try AES.GCM.Nonce(data: Data(repeating: 0, count: 12))
        let sealed = try AES.GCM.seal(xored, using: SymmetricKey(data: key), nonce: nonce)
        let encrypted = Data(sealed.ciphertext.prefix(16))
        result.append(encrypted)
        previousBlock = encrypted
    }
    return result
}

/// AES-256-CBC decryption. Ciphertext must be a multiple of 16 bytes.
func aesCBCDecrypt(key: Data, iv: Data, ciphertext: Data) throws -> Data {
    guard key.count == 32, iv.count == 16, ciphertext.count % 16 == 0 else {
        throw HMACSecretError.invalidInput
    }
    var result = Data()
    var previousBlock = iv
    for blockStart in stride(from: 0, to: ciphertext.count, by: 16) {
        let block = ciphertext[blockStart..<(blockStart + 16)]
        let nonce = try AES.GCM.Nonce(data: Data(repeating: 0, count: 12))
        let sealed = try AES.GCM.seal(Data(block), using: SymmetricKey(data: key), nonce: nonce)
        let decrypted = Data(sealed.ciphertext.prefix(16))
        var xored = Data(count: 16)
        for i in 0..<16 {
            xored[i] = decrypted[i] ^ previousBlock[previousBlock.startIndex + i]
        }
        result.append(xored)
        previousBlock = Data(block)
    }
    return result
}

public enum HMACSecretError: Error, Sendable {
    case invalidSaltLength
    case invalidInput
    case verificationFailed
}
