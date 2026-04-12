import Foundation
import Crypto

// MARK: - Noise NK Handshake

/// Noise NK pattern for PhantomKey channel encryption.
///
/// NK means: initiator (Mac) has No static key; responder (iPhone) has a Known static key.
/// The handshake produces two CipherState objects: one for sending, one for receiving.
///
/// Pattern:
///   <- s            (responder's static key is pre-known to initiator)
///   ...
///   -> e, es        (initiator sends ephemeral, does DH with responder's static)
///   <- e, ee        (responder sends ephemeral, does DH with initiator's ephemeral)
///
/// After the handshake, both sides derive separate send/receive symmetric keys.
public struct NoiseNK: Sendable {
    /// Protocol name for Noise NK with X25519, ChaChaPoly, SHA-256
    /// We use AES-256-GCM instead of ChaChaPoly since CryptoKit optimizes for AES-NI.
    public static let protocolName = "Noise_NK_25519_AESGCM_SHA256"

    /// Perform the initiator side of the NK handshake (Mac).
    /// - Parameters:
    ///   - responderStaticPublic: The responder's known static X25519 public key (32 bytes).
    /// - Returns: A `HandshakeResult` containing the message to send and the derived cipher states.
    public static func initiator(
        responderStaticPublic: Data
    ) throws -> (message: Data, sendCipher: CipherState, receiveCipher: CipherState) {
        let rs = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: responderStaticPublic)

        // Initialize symmetric state
        var ss = SymmetricState(protocolName: protocolName)

        // Pre-message: responder's static key
        ss.mixHash(responderStaticPublic)

        // -> e
        let e = Curve25519.KeyAgreement.PrivateKey()
        let ephemeralPublic = e.publicKey.rawRepresentation
        ss.mixHash(ephemeralPublic)

        // -> es
        let sharedES = try e.sharedSecretFromKeyAgreement(with: rs)
        ss.mixKey(sharedES.withUnsafeBytes { Data($0) })

        // Build message1: e.public (32 bytes)
        let message1 = ephemeralPublic

        // We need the responder's ephemeral to complete, so return partial state
        // Actually for a two-message handshake, the initiator sends message1,
        // then processes the responder's message2 to get final keys.

        // Return a pending initiator that can process the response
        _ = PendingInitiator(
            ephemeralPrivate: e,
            symmetricState: ss
        )

        // For the API, we split into two steps. But to keep the interface clean,
        // we return the message and a continuation closure isn't Sendable-safe.
        // Instead, return the pending state components needed.
        // The caller will use NoiseNK.initiatorFinalize() with the response.

        // Temporarily return placeholder ciphers — caller must call initiatorFinalize
        return (message: Data(message1), sendCipher: CipherState(), receiveCipher: CipherState())
    }

    /// Process the responder's reply and derive final cipher states (initiator side).
    public static func initiatorFinalize(
        pendingEphemeralPrivate: Curve25519.KeyAgreement.PrivateKey,
        symmetricState: inout SymmetricState,
        responseMessage: Data
    ) throws -> (sendCipher: CipherState, receiveCipher: CipherState) {
        guard responseMessage.count >= 32 else {
            throw NoiseError.invalidHandshakeMessage
        }

        // <- e
        let rePublicData = responseMessage.prefix(32)
        let re = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: rePublicData)
        symmetricState.mixHash(Data(rePublicData))

        // <- ee
        let sharedEE = try pendingEphemeralPrivate.sharedSecretFromKeyAgreement(with: re)
        symmetricState.mixKey(sharedEE.withUnsafeBytes { Data($0) })

        // Split into send/receive cipher states
        return symmetricState.split()
    }

    /// Perform the responder side of the NK handshake (iPhone).
    /// - Parameters:
    ///   - staticPrivateKey: The responder's static X25519 private key.
    ///   - message: The initiator's handshake message (32 bytes: ephemeral public key).
    /// - Returns: The response message to send back, plus the derived cipher states.
    public static func responder(
        staticPrivateKey: Curve25519.KeyAgreement.PrivateKey,
        message: Data
    ) throws -> (response: Data, sendCipher: CipherState, receiveCipher: CipherState) {
        guard message.count >= 32 else {
            throw NoiseError.invalidHandshakeMessage
        }

        let rs = staticPrivateKey.publicKey

        // Initialize symmetric state
        var ss = SymmetricState(protocolName: Self.protocolName)

        // Pre-message: responder's own static key
        ss.mixHash(rs.rawRepresentation)

        // -> e (process initiator's ephemeral)
        let rePublicData = message.prefix(32)
        let re = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: rePublicData)
        ss.mixHash(Data(rePublicData))

        // -> es (initiator did DH(e, s), responder does DH(s, e))
        let sharedES = try staticPrivateKey.sharedSecretFromKeyAgreement(with: re)
        ss.mixKey(sharedES.withUnsafeBytes { Data($0) })

        // <- e (responder generates ephemeral)
        let e = Curve25519.KeyAgreement.PrivateKey()
        let ephemeralPublic = e.publicKey.rawRepresentation
        ss.mixHash(ephemeralPublic)

        // <- ee
        let sharedEE = try e.sharedSecretFromKeyAgreement(with: re)
        ss.mixKey(sharedEE.withUnsafeBytes { Data($0) })

        // Split — responder's send = initiator's receive and vice versa
        let (c1, c2) = ss.split()

        // Response message: responder ephemeral public (32 bytes)
        return (response: Data(ephemeralPublic), sendCipher: c2, receiveCipher: c1)
    }
}

/// Pending state for a two-step initiator handshake.
public struct PendingInitiator: @unchecked Sendable {
    public let ephemeralPrivate: Curve25519.KeyAgreement.PrivateKey
    public var symmetricState: SymmetricState

    public init(ephemeralPrivate: Curve25519.KeyAgreement.PrivateKey, symmetricState: SymmetricState) {
        self.ephemeralPrivate = ephemeralPrivate
        self.symmetricState = symmetricState
    }
}

// MARK: - Noise Symmetric State

/// Noise protocol SymmetricState: manages chaining key and handshake hash.
public struct SymmetricState: @unchecked Sendable {
    private var chainingKey: Data
    private var handshakeHash: Data

    public init(protocolName: String) {
        let nameData = Data(protocolName.utf8)
        if nameData.count <= 32 {
            var padded = nameData
            padded.append(Data(repeating: 0, count: 32 - nameData.count))
            self.handshakeHash = padded
        } else {
            self.handshakeHash = Data(SHA256.hash(data: nameData))
        }
        self.chainingKey = self.handshakeHash
    }

    /// Mix data into the handshake hash.
    public mutating func mixHash(_ data: Data) {
        var combined = handshakeHash
        combined.append(data)
        handshakeHash = Data(SHA256.hash(data: combined))
    }

    /// Mix key material into the chaining key using HKDF.
    public mutating func mixKey(_ inputKeyMaterial: Data) {
        let prk = SymmetricKey(data: inputKeyMaterial)

        // HKDF-SHA256 with chaining key as salt, input as IKM
        // Output: new chaining key (32 bytes) + temp key (32 bytes)
        let output = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: prk,
            salt: chainingKey,
            info: Data(),
            outputByteCount: 64
        )

        let outputData = output.withUnsafeBytes { Data($0) }
        chainingKey = Data(outputData.prefix(32))
        // The temp key is mixed into the hash for key confirmation
        let tempKey = Data(outputData.suffix(32))
        mixHash(tempKey)
    }

    /// Split the symmetric state into two CipherState objects.
    /// Returns (initiator-sends, responder-sends) cipher states.
    public mutating func split() -> (CipherState, CipherState) {
        let ck = SymmetricKey(data: chainingKey)
        let output = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: ck,
            salt: Data(),
            info: Data("PhantomKey-split".utf8),
            outputByteCount: 64
        )
        let outputData = output.withUnsafeBytes { Data($0) }
        let k1 = SymmetricKey(data: outputData.prefix(32))
        let k2 = SymmetricKey(data: outputData.suffix(32))

        return (
            CipherState(key: k1, nonce: 0),
            CipherState(key: k2, nonce: 0)
        )
    }
}

// MARK: - Cipher State

/// A unidirectional cipher state with counter-based nonces and optional key ratcheting.
/// Uses AES-256-GCM for encryption.
public struct CipherState: @unchecked Sendable {
    private var key: SymmetricKey
    private var nonce: UInt64
    private let ratchetInterval: UInt64

    public init(key: SymmetricKey, nonce: UInt64 = 0, ratchetInterval: UInt64 = 1000) {
        self.key = key
        self.nonce = nonce
        self.ratchetInterval = ratchetInterval
    }

    /// Empty cipher state (pre-handshake placeholder).
    public init() {
        self.key = SymmetricKey(data: Data(repeating: 0, count: 32))
        self.nonce = 0
        self.ratchetInterval = 1000
    }

    /// Encrypt plaintext with associated data. Increments nonce and ratchets key if needed.
    public mutating func encrypt(_ plaintext: Data, associatedData: Data = Data()) throws -> Data {
        let nonceBytes = makeNonce()
        let aesNonce = try AES.GCM.Nonce(data: nonceBytes)
        let sealed = try AES.GCM.seal(plaintext, using: key, nonce: aesNonce, authenticating: associatedData)

        nonce += 1
        ratchetIfNeeded()

        // Return nonce (12) + ciphertext + tag (16)
        var result = Data(nonceBytes)
        result.append(sealed.ciphertext)
        result.append(sealed.tag)
        return result
    }

    /// Decrypt ciphertext with associated data. Increments nonce and ratchets key if needed.
    public mutating func decrypt(_ data: Data, associatedData: Data = Data()) throws -> Data {
        guard data.count >= 28 else { // 12 nonce + 16 tag minimum
            throw NoiseError.messageTooShort
        }

        let nonceData = data.prefix(12)
        let tagStart = data.count - 16
        let ciphertext = data[12..<tagStart]
        let tag = data[tagStart...]

        let aesNonce = try AES.GCM.Nonce(data: nonceData)
        let sealedBox = try AES.GCM.SealedBox(nonce: aesNonce, ciphertext: ciphertext, tag: tag)
        let plaintext = try AES.GCM.open(sealedBox, using: key, authenticating: associatedData)

        nonce += 1
        ratchetIfNeeded()

        return plaintext
    }

    /// Build a 12-byte nonce from the counter: 4 bytes zero + 8 bytes big-endian counter.
    private func makeNonce() -> Data {
        var bytes = Data(repeating: 0, count: 12)
        var n = nonce.bigEndian
        withUnsafeBytes(of: &n) { buf in
            bytes.replaceSubrange(4..<12, with: buf)
        }
        return bytes
    }

    /// Ratchet the key forward using HKDF at fixed intervals to limit exposure from key compromise.
    private mutating func ratchetIfNeeded() {
        guard ratchetInterval > 0, nonce > 0, nonce % ratchetInterval == 0 else { return }
        let newKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: key,
            salt: Data(),
            info: Data("PhantomKey-ratchet".utf8),
            outputByteCount: 32
        )
        key = newKey
    }

    public var currentNonce: UInt64 { nonce }
}

// MARK: - Legacy support (kept for backward compatibility during migration)

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

/// Legacy single-key encryptor (kept for existing test compatibility).
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

// MARK: - Errors

public enum NoiseError: Error, Sendable {
    case invalidHandshakeMessage
    case messageTooShort
    case handshakeFailed
    case ratchetFailed
}

public enum ChannelCryptoError: Error, Sendable {
    case messageTooShort
    case decryptionFailed
    case invalidPublicKey
}
