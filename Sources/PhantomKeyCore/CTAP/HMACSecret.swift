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
            return constantTimeEqual(expected.prefix(16), saltAuth)
        case .v2:
            return constantTimeEqual(expected, saltAuth)
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

// MARK: - AES-CBC via CommonCrypto (correct implementation for PIN protocol)

#if canImport(CommonCrypto)
import CommonCrypto

/// AES-256-CBC encryption. Plaintext must be a multiple of 16 bytes (no padding applied).
func aesCBCEncrypt(key: Data, iv: Data, plaintext: Data) throws -> Data {
    guard key.count == 32, iv.count == 16, plaintext.count % 16 == 0 else {
        throw HMACSecretError.invalidInput
    }
    let outputSize = plaintext.count
    var result = Data(count: outputSize)
    var numBytesEncrypted: size_t = 0
    let status = result.withUnsafeMutableBytes { resultPtr in
        plaintext.withUnsafeBytes { plaintextPtr in
            key.withUnsafeBytes { keyPtr in
                iv.withUnsafeBytes { ivPtr in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(0),
                        keyPtr.baseAddress, key.count,
                        ivPtr.baseAddress,
                        plaintextPtr.baseAddress, plaintext.count,
                        resultPtr.baseAddress, outputSize,
                        &numBytesEncrypted
                    )
                }
            }
        }
    }
    guard status == kCCSuccess else { throw HMACSecretError.invalidInput }
    return Data(result.prefix(numBytesEncrypted))
}

/// AES-256-CBC decryption. Ciphertext must be a multiple of 16 bytes.
func aesCBCDecrypt(key: Data, iv: Data, ciphertext: Data) throws -> Data {
    guard key.count == 32, iv.count == 16, ciphertext.count % 16 == 0 else {
        throw HMACSecretError.invalidInput
    }
    let outputSize = ciphertext.count
    var result = Data(count: outputSize)
    var numBytesDecrypted: size_t = 0
    let status = result.withUnsafeMutableBytes { resultPtr in
        ciphertext.withUnsafeBytes { ciphertextPtr in
            key.withUnsafeBytes { keyPtr in
                iv.withUnsafeBytes { ivPtr in
                    CCCrypt(
                        CCOperation(kCCDecrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(0),
                        keyPtr.baseAddress, key.count,
                        ivPtr.baseAddress,
                        ciphertextPtr.baseAddress, ciphertext.count,
                        resultPtr.baseAddress, outputSize,
                        &numBytesDecrypted
                    )
                }
            }
        }
    }
    guard status == kCCSuccess else { throw HMACSecretError.invalidInput }
    return Data(result.prefix(numBytesDecrypted))
}
#else
// Fallback for non-Apple platforms.
// TODO: Use _CryptoExtras AES._CBC for Linux support.
func aesCBCEncrypt(key: Data, iv: Data, plaintext: Data) throws -> Data {
    fatalError("AES-CBC requires CommonCrypto (Apple platforms)")
}

func aesCBCDecrypt(key: Data, iv: Data, ciphertext: Data) throws -> Data {
    fatalError("AES-CBC requires CommonCrypto (Apple platforms)")
}
#endif

public enum HMACSecretError: Error, Sendable {
    case invalidSaltLength
    case invalidInput
    case verificationFailed
}

// MARK: - Constant-time comparison

/// Compares two byte sequences in constant time to prevent timing side-channel attacks.
/// Returns true only if both sequences have equal length and identical contents.
func constantTimeEqual<L: DataProtocol, R: DataProtocol>(_ lhs: L, _ rhs: R) -> Bool {
    guard lhs.count == rhs.count else { return false }
    var diff: UInt8 = 0
    for (a, b) in zip(lhs, rhs) {
        diff |= a ^ b
    }
    return diff == 0
}
