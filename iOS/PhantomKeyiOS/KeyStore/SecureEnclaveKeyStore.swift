#if canImport(Security) && canImport(UIKit)
import Foundation
import Security
import CryptoKit
import LocalAuthentication
import PhantomKeyCore

actor SecureEnclaveKeyStore: CredentialStore {
    private let accessGroup: String?

    init(accessGroup: String? = nil) {
        self.accessGroup = accessGroup
    }

    func store(credential: StoredCredential) async throws {
        let context = LAContext()
        context.localizedReason = "Create credential for \(credential.relyingPartyName)"

        // Generate a Secure Enclave P-256 signing key using CryptoKit
        let privateKey = try SecureEnclave.P256.Signing.PrivateKey(
            accessControl: createAccessControl(),
            authenticationContext: context
        )

        // Store the key's data representation in Keychain for later retrieval
        let metadata = CredentialMetadata(
            credentialId: credential.credentialId,
            relyingPartyId: credential.relyingPartyId,
            relyingPartyName: credential.relyingPartyName,
            userId: credential.userId,
            userName: credential.userName,
            userDisplayName: credential.userDisplayName,
            algorithm: credential.algorithm,
            createdAt: credential.createdAt,
            isResident: credential.isResident,
            credProtect: credential.credProtect,
            largeBlobKey: credential.largeBlobKey,
            hmacSecret: credential.hmacSecret,
            privateKeyDataRepresentation: privateKey.dataRepresentation
        )

        let data = try JSONEncoder().encode(metadata)
        var metadataQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "md.thomas.phantomkey.credentials",
            kSecAttrAccount as String: credential.credentialId.base64EncodedString(),
            kSecValueData as String: data,
        ]

        if let group = accessGroup {
            metadataQuery[kSecAttrAccessGroup as String] = group
        }

        let status = SecItemAdd(metadataQuery as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeyStoreError.metadataStoreFailed(status)
        }
    }

    func find(relyingPartyId: String, credentialId: Data?) async throws -> [StoredCredential] {
        let allMetadata = try loadAllMetadata()

        return allMetadata
            .filter { $0.relyingPartyId == relyingPartyId }
            .filter { credentialId == nil || $0.credentialId == credentialId }
            .map { $0.toStoredCredential() }
    }

    func findAll(relyingPartyId: String) async throws -> [StoredCredential] {
        try await find(relyingPartyId: relyingPartyId, credentialId: nil)
    }

    func delete(credentialId: Data) async throws {
        let metaQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "md.thomas.phantomkey.credentials",
            kSecAttrAccount as String: credentialId.base64EncodedString(),
        ]
        SecItemDelete(metaQuery as CFDictionary)
    }

    func enumerateRelyingParties() async throws -> [String] {
        let allMetadata = try loadAllMetadata()
        let rpIds = Set(allMetadata.map(\.relyingPartyId))
        return Array(rpIds).sorted()
    }

    func countResidentCredentials() async throws -> Int {
        let allMetadata = try loadAllMetadata()
        return allMetadata.filter(\.isResident).count
    }

    func maxResidentCredentials() -> Int {
        128
    }

    func update(credentialId: Data, userName: String, userDisplayName: String) async throws {
        let account = credentialId.base64EncodedString()
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "md.thomas.phantomkey.credentials",
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else {
            throw KeyStoreError.keyNotFound
        }

        var metadata = try JSONDecoder().decode(CredentialMetadata.self, from: data)
        metadata.userName = userName
        metadata.userDisplayName = userDisplayName

        let updatedData = try JSONEncoder().encode(metadata)
        let updateQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "md.thomas.phantomkey.credentials",
            kSecAttrAccount as String: account,
        ]
        let attrs: [String: Any] = [
            kSecValueData as String: updatedData,
        ]
        SecItemUpdate(updateQuery as CFDictionary, attrs as CFDictionary)
    }

    /// Sign data using the Secure Enclave P-256 key via CryptoKit.
    func sign(credentialId: Data, data: Data) async throws -> Data {
        let allMetadata = try loadAllMetadata()
        guard let meta = allMetadata.first(where: { $0.credentialId == credentialId }),
              let keyData = meta.privateKeyDataRepresentation else {
            throw KeyStoreError.keyNotFound
        }

        let context = LAContext()
        context.localizedReason = "Authenticate with \(meta.relyingPartyName)"

        let privateKey = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: keyData,
            authenticationContext: context
        )

        let signature = try privateKey.signature(for: data)
        return signature.derRepresentation
    }

    private func createAccessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &error
        ) else {
            throw KeyStoreError.accessControlFailed
        }
        return access
    }

    private func loadAllMetadata() throws -> [CredentialMetadata] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "md.thomas.phantomkey.credentials",
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]

        var items: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &items)

        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let dataArray = items as? [Data] else {
            throw KeyStoreError.metadataLoadFailed(status)
        }

        return dataArray.compactMap { try? JSONDecoder().decode(CredentialMetadata.self, from: $0) }
    }
}

struct CredentialMetadata: Codable {
    let credentialId: Data
    let relyingPartyId: String
    let relyingPartyName: String
    let userId: Data
    var userName: String
    var userDisplayName: String
    let algorithm: Int
    let createdAt: Date
    let isResident: Bool
    let credProtect: UInt8?
    let largeBlobKey: Data?
    let hmacSecret: Data?
    let privateKeyDataRepresentation: Data?

    init(
        credentialId: Data,
        relyingPartyId: String,
        relyingPartyName: String,
        userId: Data,
        userName: String,
        userDisplayName: String,
        algorithm: Int,
        createdAt: Date,
        isResident: Bool,
        credProtect: UInt8? = nil,
        largeBlobKey: Data? = nil,
        hmacSecret: Data? = nil,
        privateKeyDataRepresentation: Data? = nil
    ) {
        self.credentialId = credentialId
        self.relyingPartyId = relyingPartyId
        self.relyingPartyName = relyingPartyName
        self.userId = userId
        self.userName = userName
        self.userDisplayName = userDisplayName
        self.algorithm = algorithm
        self.createdAt = createdAt
        self.isResident = isResident
        self.credProtect = credProtect
        self.largeBlobKey = largeBlobKey
        self.hmacSecret = hmacSecret
        self.privateKeyDataRepresentation = privateKeyDataRepresentation
    }

    func toStoredCredential() -> StoredCredential {
        StoredCredential(
            credentialId: credentialId,
            relyingPartyId: relyingPartyId,
            relyingPartyName: relyingPartyName,
            userId: userId,
            userName: userName,
            userDisplayName: userDisplayName,
            privateKeySerialized: privateKeyDataRepresentation ?? Data(),
            algorithm: algorithm,
            createdAt: createdAt,
            isResident: isResident,
            signatureCounter: 0,
            credProtect: credProtect,
            largeBlobKey: largeBlobKey,
            hmacSecret: hmacSecret
        )
    }
}

enum KeyStoreError: Error {
    case keyGenerationFailed(String)
    case metadataStoreFailed(OSStatus)
    case metadataLoadFailed(OSStatus)
    case keyNotFound
    case signingFailed(String)
    case accessControlFailed
}
#endif
