import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

public enum AuthenticatorError: Error, Sendable {
    case unsupportedAlgorithm
    case credentialNotFound
    case operationDenied
    case invalidRequest
    case signingFailed
    case timeout
    case pinRequired
    case uvBlocked
    case storageFull
}

public protocol CredentialStore: Sendable {
    func store(credential: StoredCredential) async throws
    func find(relyingPartyId: String, credentialId: Data?) async throws -> [StoredCredential]
    func findAll(relyingPartyId: String) async throws -> [StoredCredential]
    func delete(credentialId: Data) async throws
    func enumerateRelyingParties() async throws -> [String]
    func countResidentCredentials() async throws -> Int
    func maxResidentCredentials() -> Int
    func update(credentialId: Data, userName: String, userDisplayName: String) async throws
}

public struct StoredCredential: Sendable, Codable {
    public let credentialId: Data
    public let relyingPartyId: String
    public let relyingPartyName: String
    public let userId: Data
    public var userName: String
    public var userDisplayName: String
    public let privateKeySerialized: Data
    public let algorithm: Int
    public let createdAt: Date
    public let isResident: Bool
    public var signatureCounter: UInt32
    public let credProtect: UInt8?
    public var largeBlobKey: Data?
    public let hmacSecret: Data?

    public init(
        credentialId: Data,
        relyingPartyId: String,
        relyingPartyName: String,
        userId: Data,
        userName: String,
        userDisplayName: String,
        privateKeySerialized: Data,
        algorithm: Int,
        createdAt: Date = Date(),
        isResident: Bool = false,
        signatureCounter: UInt32 = 0,
        credProtect: UInt8? = nil,
        largeBlobKey: Data? = nil,
        hmacSecret: Data? = nil
    ) {
        self.credentialId = credentialId
        self.relyingPartyId = relyingPartyId
        self.relyingPartyName = relyingPartyName
        self.userId = userId
        self.userName = userName
        self.userDisplayName = userDisplayName
        self.privateKeySerialized = privateKeySerialized
        self.algorithm = algorithm
        self.createdAt = createdAt
        self.isResident = isResident
        self.signatureCounter = signatureCounter
        self.credProtect = credProtect
        self.largeBlobKey = largeBlobKey
        self.hmacSecret = hmacSecret
    }

    public mutating func incrementCounter() {
        signatureCounter &+= 1
    }
}

public struct AuthenticatorInfo: Sendable {
    public let versions: [String]
    public let extensions: [String]
    public let aaguid: Data
    public let maxMsgSize: Int
    public let pinProtocols: [Int]
    public let maxCredentialCountInList: Int
    public let maxCredentialIdLength: Int
    public let transports: [String]
    public let options: [String: Bool]
    public let maxSerializedLargeBlobArray: Int?
    public let remainingDiscoverableCredentials: Int?

    public static let phantomKey = AuthenticatorInfo(
        versions: ["FIDO_2_0", "FIDO_2_1", "U2F_V2"],
        extensions: ["credProtect", "hmac-secret", "largeBlobKey"],
        aaguid: Data(repeating: 0xAA, count: 16),
        maxMsgSize: 1200,
        pinProtocols: [2, 1],
        maxCredentialCountInList: 8,
        maxCredentialIdLength: 128,
        transports: ["internal", "hybrid"],
        options: [
            "rk": true,
            "up": true,
            "uv": true,
            "plat": false,
            "credMgmt": true,
            "largeBlobs": true,
            "alwaysUv": true,
            "makeCredUvNotRqd": false,
        ],
        maxSerializedLargeBlobArray: 4096,
        remainingDiscoverableCredentials: nil
    )

    public func toCBOR() -> CBORValue {
        var map: [(CBORValue, CBORValue)] = []

        // 0x01 - versions
        map.append((
            .unsignedInt(0x01),
            .array(versions.map { .textString($0) })
        ))

        // 0x02 - extensions
        if !extensions.isEmpty {
            map.append((
                .unsignedInt(0x02),
                .array(extensions.map { .textString($0) })
            ))
        }

        // 0x03 - aaguid
        map.append((
            .unsignedInt(0x03),
            .byteString(aaguid)
        ))

        // 0x04 - options
        var optionsMap: [(CBORValue, CBORValue)] = []
        for (key, val) in options.sorted(by: { $0.key < $1.key }) {
            optionsMap.append((.textString(key), .bool(val)))
        }
        map.append((
            .unsignedInt(0x04),
            .map(optionsMap)
        ))

        // 0x05 - maxMsgSize
        map.append((
            .unsignedInt(0x05),
            .unsignedInt(UInt64(maxMsgSize))
        ))

        // 0x06 - pinUvAuthProtocols
        map.append((
            .unsignedInt(0x06),
            .array(pinProtocols.map { .unsignedInt(UInt64($0)) })
        ))

        // 0x07 - maxCredentialCountInList
        map.append((
            .unsignedInt(0x07),
            .unsignedInt(UInt64(maxCredentialCountInList))
        ))

        // 0x08 - maxCredentialIdLength
        map.append((
            .unsignedInt(0x08),
            .unsignedInt(UInt64(maxCredentialIdLength))
        ))

        // 0x09 - transports
        map.append((
            .unsignedInt(0x09),
            .array(transports.map { .textString($0) })
        ))

        // 0x0B - maxSerializedLargeBlobArray
        if let maxBlob = maxSerializedLargeBlobArray {
            map.append((
                .unsignedInt(0x0B),
                .unsignedInt(UInt64(maxBlob))
            ))
        }

        // 0x0E - remainingDiscoverableCredentials
        if let remaining = remainingDiscoverableCredentials {
            map.append((
                .unsignedInt(0x0E),
                .unsignedInt(UInt64(remaining))
            ))
        }

        return .map(map)
    }
}

public struct AuthenticatorData: Sendable {
    public let rpIdHash: Data
    public let flags: UInt8
    public let signCount: UInt32
    public let attestedCredentialData: Data?
    public let extensions: Data?

    public static let flagUserPresent: UInt8 = 0x01
    public static let flagUserVerified: UInt8 = 0x04
    public static let flagAttestedCredential: UInt8 = 0x40
    public static let flagExtensionData: UInt8 = 0x80

    public init(
        rpIdHash: Data,
        flags: UInt8,
        signCount: UInt32,
        attestedCredentialData: Data? = nil,
        extensions: Data? = nil
    ) {
        self.rpIdHash = rpIdHash
        self.flags = flags
        self.signCount = signCount
        self.attestedCredentialData = attestedCredentialData
        self.extensions = extensions
    }

    public func serialize() -> Data {
        var data = Data()
        data.append(rpIdHash)
        data.append(flags)
        var counter = signCount.bigEndian
        data.append(Data(bytes: &counter, count: 4))
        if let attested = attestedCredentialData {
            data.append(attested)
        }
        if let ext = extensions {
            data.append(ext)
        }
        return data
    }

    public static func makeRpIdHash(_ rpId: String) -> Data {
        Data(SHA256.hash(data: Data(rpId.utf8)))
    }
}
