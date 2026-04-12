#if canImport(Security) && canImport(UIKit)
import Foundation
import Security
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

        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: credential.credentialId,
                kSecAttrAccessControl as String: try createAccessControl(),
                kSecUseAuthenticationContext as String: context,
            ] as [String: Any],
        ]

        if let group = accessGroup {
            attributes[kSecAttrAccessGroup as String] = group
        }

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw KeyStoreError.keyGenerationFailed(error?.takeRetainedValue().localizedDescription ?? "Unknown")
        }

        let metadata = CredentialMetadata(
            credentialId: credential.credentialId,
            relyingPartyId: credential.relyingPartyId,
            relyingPartyName: credential.relyingPartyName,
            userId: credential.userId,
            userName: credential.userName,
            userDisplayName: credential.userDisplayName,
            algorithm: credential.algorithm,
            createdAt: credential.createdAt,
            isResident: credential.isResident
        )

        let data = try JSONEncoder().encode(metadata)
        let metadataQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "md.thomas.phantomkey.credentials",
            kSecAttrAccount as String: credential.credentialId.base64EncodedString(),
            kSecValueData as String: data,
        ]

        let status = SecItemAdd(metadataQuery as CFDictionary, nil)
        guard status == errSecSuccess else {
            SecKeyCreateRandomKey([:] as CFDictionary, nil) // cleanup attempt
            throw KeyStoreError.metadataStoreFailed(status)
        }

        _ = privateKey // key is persisted in Secure Enclave
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
        let keyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: credentialId,
        ]
        SecItemDelete(keyQuery as CFDictionary)

        let metaQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "md.thomas.phantomkey.credentials",
            kSecAttrAccount as String: credentialId.base64EncodedString(),
        ]
        SecItemDelete(metaQuery as CFDictionary)
    }

    func sign(credentialId: Data, data: Data) async throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: credentialId,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let privateKey = item else {
            throw KeyStoreError.keyNotFound
        }

        guard let secKey = privateKey as? SecKey else {
            throw KeyStoreError.keyNotFound
        }
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            secKey,
            .ecdsaSignatureMessageX962SHA256,
            data as CFData,
            &error
        ) else {
            throw KeyStoreError.signingFailed(error?.takeRetainedValue().localizedDescription ?? "Unknown")
        }

        return signature as Data
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
    let userName: String
    let userDisplayName: String
    let algorithm: Int
    let createdAt: Date
    let isResident: Bool

    func toStoredCredential() -> StoredCredential {
        StoredCredential(
            credentialId: credentialId,
            relyingPartyId: relyingPartyId,
            relyingPartyName: relyingPartyName,
            userId: userId,
            userName: userName,
            userDisplayName: userDisplayName,
            privateKeySerialized: Data(),
            algorithm: algorithm,
            createdAt: createdAt,
            isResident: isResident,
            signatureCounter: 0
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
