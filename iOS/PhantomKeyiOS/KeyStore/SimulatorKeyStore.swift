#if targetEnvironment(simulator)
import Foundation
import CryptoKit
import PhantomKeyCore

/// A software-backed credential store for iOS Simulator use.
/// Uses in-memory storage with regular P256 keys (no Secure Enclave).
actor SimulatorKeyStore: @preconcurrency CredentialStore {
    private var credentials: [StoredCredential] = []

    func store(credential: StoredCredential) async throws {
        // Preserve the caller's key material. If the credential was created
        // without a private key (e.g. from a registration flow that only knows
        // the public key), generate a software one and replace it.
        if credential.privateKeySerialized.isEmpty {
            let privateKey = P256.Signing.PrivateKey()
            let cred = StoredCredential(
                credentialId: credential.credentialId,
                relyingPartyId: credential.relyingPartyId,
                relyingPartyName: credential.relyingPartyName,
                userId: credential.userId,
                userName: credential.userName,
                userDisplayName: credential.userDisplayName,
                privateKeySerialized: privateKey.rawRepresentation,
                algorithm: credential.algorithm,
                createdAt: credential.createdAt,
                isResident: credential.isResident,
                signatureCounter: credential.signatureCounter,
                credProtect: credential.credProtect,
                largeBlobKey: credential.largeBlobKey,
                hmacSecret: credential.hmacSecret
            )
            credentials.append(cred)
        } else {
            credentials.append(credential)
        }
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
#endif
