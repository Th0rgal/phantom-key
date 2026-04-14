import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// A simple TCP-based signing service for simulator testing.
/// The iOS app runs the server; the SSH agent connects as a client.
/// Protocol: 4-byte big-endian length prefix + Envelope (unencrypted, localhost only).
public enum LoopbackSigningService {
    public static let defaultPort: UInt16 = 7878

    // MARK: - Wire helpers

    public static func sendMessage(_ fd: Int32, envelope: Envelope) throws {
        let data = envelope.serialize()
        var len = UInt32(data.count).bigEndian
        let lenData = Data(bytes: &len, count: 4)
        try writeAll(fd, lenData)
        try writeAll(fd, data)
    }

    public static func receiveMessage(_ fd: Int32) throws -> Envelope {
        let lenData = try readAll(fd, count: 4)
        let msgLen = Int(UInt32(lenData[0]) << 24 | UInt32(lenData[1]) << 16
            | UInt32(lenData[2]) << 8 | UInt32(lenData[3]))
        guard msgLen > 0, msgLen < 256 * 1024 else {
            throw TransportError.receiveFailed("invalid length: \(msgLen)")
        }
        let data = try readAll(fd, count: msgLen)
        return try Envelope.deserialize(data)
    }

    // MARK: - Client: connect to signing service

    public static func connect(port: UInt16 = defaultPort) throws -> Int32 {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw TransportError.sendFailed("socket() failed") }

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")

        let result = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                Darwin.connect(fd, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard result == 0 else {
            close(fd)
            throw TransportError.sendFailed("connect() failed: errno \(errno)")
        }
        return fd
    }

    // MARK: - Make Credential via loopback

    /// Register a new credential with the iOS authenticator.
    /// Returns (credentialId, P256 public key).
    public static func makeCredential(
        fd: Int32,
        rpId: String,
        rpName: String,
        userId: Data,
        userName: String,
        userDisplayName: String
    ) throws -> (credentialId: Data, publicKey: P256.Signing.PublicKey) {
        let clientDataHash = Data(SHA256.hash(data: Data("phantomkey-ssh-\(rpId)".utf8)))

        let payload = CBOREncoder().encode(.map([
            (.unsignedInt(1), .byteString(clientDataHash)),
            (.unsignedInt(2), .map([
                (.textString("id"), .textString(rpId)),
                (.textString("name"), .textString(rpName)),
            ])),
            (.unsignedInt(3), .map([
                (.textString("id"), .byteString(userId)),
                (.textString("name"), .textString(userName)),
                (.textString("displayName"), .textString(userDisplayName)),
            ])),
            (.unsignedInt(4), .array([
                .map([
                    (.textString("type"), .textString("public-key")),
                    (.textString("alg"), .negativeInt(-7)),
                ]),
            ])),
        ]))

        let request = Envelope(type: .makeCredentialRequest, sequence: 0, payload: payload)
        try sendMessage(fd, envelope: request)
        let response = try receiveMessage(fd)
        guard response.type == .makeCredentialResponse else {
            throw AuthenticatorError.invalidRequest
        }

        // Parse response to extract credentialId and public key
        let decoded = try CBORDecoder().decode(response.payload)
        guard case .map(let pairs) = decoded else { throw AuthenticatorError.invalidRequest }

        let credIdEntry = pairs.first { $0.0 == .unsignedInt(2) }
        guard case .byteString(let credId) = credIdEntry?.1 else {
            throw AuthenticatorError.invalidRequest
        }

        // Extract public key from attestation object
        let attEntry = pairs.first { $0.0 == .unsignedInt(1) }
        guard case .byteString(let attObjData) = attEntry?.1 else {
            throw AuthenticatorError.invalidRequest
        }

        let attObj = try CBORDecoder().decode(attObjData)
        guard case .map(let attPairs) = attObj else { throw AuthenticatorError.invalidRequest }

        let authDataEntry = attPairs.first { $0.0 == .textString("authData") }
        guard case .byteString(let authDataBytes) = authDataEntry?.1 else {
            throw AuthenticatorError.invalidRequest
        }

        // Parse authData to extract public key COSE from attested credential data
        // authData: rpIdHash(32) + flags(1) + signCount(4) + attestedCredData(...)
        // attestedCredData: aaguid(16) + credIdLen(2) + credId(N) + publicKeyCOSE(...)
        guard authDataBytes.count > 37 else { throw AuthenticatorError.invalidRequest }
        let attestedStart = 37
        guard authDataBytes.count > attestedStart + 18 else { throw AuthenticatorError.invalidRequest }
        let credIdLen = Int(authDataBytes[attestedStart + 16]) << 8 | Int(authDataBytes[attestedStart + 17])
        let coseStart = attestedStart + 18 + credIdLen
        guard authDataBytes.count > coseStart else { throw AuthenticatorError.invalidRequest }
        let coseData = Data(authDataBytes[coseStart...])

        // Decode COSE key to extract x,y coordinates
        let coseKey = try CBORDecoder().decode(coseData)
        guard case .map(let cosePairs) = coseKey else { throw AuthenticatorError.invalidRequest }

        let xEntry = cosePairs.first { $0.0 == .negativeInt(-2) }
        let yEntry = cosePairs.first { $0.0 == .negativeInt(-3) }
        guard case .byteString(let x) = xEntry?.1,
              case .byteString(let y) = yEntry?.1 else {
            throw AuthenticatorError.invalidRequest
        }

        var rawKey = Data()
        rawKey.append(x)
        rawKey.append(y)
        let publicKey = try P256.Signing.PublicKey(rawRepresentation: rawKey)

        return (credId, publicKey)
    }

    // MARK: - Get Assertion via loopback

    /// Request a signature from the iOS authenticator.
    /// Returns (authenticatorData, signature DER).
    public static func getAssertion(
        fd: Int32,
        rpId: String,
        clientDataHash: Data,
        credentialId: Data
    ) throws -> (authData: Data, signature: Data) {
        let payload = CBOREncoder().encode(.map([
            (.unsignedInt(1), .textString(rpId)),
            (.unsignedInt(2), .byteString(clientDataHash)),
            (.unsignedInt(3), .array([
                .map([
                    (.textString("type"), .textString("public-key")),
                    (.textString("id"), .byteString(credentialId)),
                ]),
            ])),
        ]))

        let request = Envelope(type: .getAssertionRequest, sequence: 0, payload: payload)
        try sendMessage(fd, envelope: request)
        let response = try receiveMessage(fd)
        guard response.type == .getAssertionResponse else {
            throw AuthenticatorError.signingFailed
        }

        let decoded = try CBORDecoder().decode(response.payload)
        guard case .map(let pairs) = decoded else { throw AuthenticatorError.invalidRequest }

        let authDataEntry = pairs.first { $0.0 == .unsignedInt(2) }
        guard case .byteString(let authData) = authDataEntry?.1 else {
            throw AuthenticatorError.invalidRequest
        }

        let sigEntry = pairs.first { $0.0 == .unsignedInt(3) }
        guard case .byteString(let sig) = sigEntry?.1 else {
            throw AuthenticatorError.invalidRequest
        }

        return (authData, sig)
    }

    // MARK: - Socket I/O

    private static func writeAll(_ fd: Int32, _ data: Data) throws {
        try data.withUnsafeBytes { buf in
            var written = 0
            while written < buf.count {
                let n = write(fd, buf.baseAddress! + written, buf.count - written)
                guard n > 0 else { throw TransportError.sendFailed("write failed") }
                written += n
            }
        }
    }

    private static func readAll(_ fd: Int32, count: Int) throws -> Data {
        var buffer = [UInt8](repeating: 0, count: count)
        var totalRead = 0
        while totalRead < count {
            let n = read(fd, &buffer[totalRead], count - totalRead)
            guard n > 0 else { throw TransportError.receiveFailed("read failed") }
            totalRead += n
        }
        return Data(buffer)
    }
}
