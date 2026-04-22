import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// CTAP 2.1 authenticatorCredentialManagement command handler.
/// Supports enumeration, deletion, and user info updates for discoverable credentials.
public actor CredentialManager {
    private let store: CredentialStore
    private var rpEnumeration: [String]?
    private var rpEnumIndex: Int = 0
    private var credEnumeration: [StoredCredential]?
    private var credEnumIndex: Int = 0

    public init(store: CredentialStore) {
        self.store = store
    }

    public func handleCommand(_ request: CredentialManagementRequest) async throws -> CredentialManagementResponse {
        switch request.subCommand {
        case .getCredsMetadata:
            return try await getCredsMetadata()
        case .enumerateRPsBegin:
            return try await enumerateRPsBegin()
        case .enumerateRPsGetNextRP:
            return try enumerateRPsGetNext()
        case .enumerateCredentialsBegin:
            return try await enumerateCredentialsBegin(params: request.subCommandParams)
        case .enumerateCredentialsGetNextCredential:
            return try enumerateCredentialsGetNext()
        case .deleteCredential:
            return try await deleteCredential(params: request.subCommandParams)
        case .updateUserInformation:
            return try await updateUserInformation(params: request.subCommandParams)
        }
    }

    private func getCredsMetadata() async throws -> CredentialManagementResponse {
        let count = try await store.countResidentCredentials()
        let max = store.maxResidentCredentials()
        return CredentialManagementResponse(
            existingResidentCredentialsCount: count,
            maxPossibleRemainingResidentCredentialsCount: max - count
        )
    }

    private func enumerateRPsBegin() async throws -> CredentialManagementResponse {
        let rps = try await store.enumerateRelyingParties()
        guard !rps.isEmpty else {
            throw CTAPError.noCredentials
        }
        rpEnumeration = rps
        rpEnumIndex = 1
        let rpId = rps[0]
        return CredentialManagementResponse(
            rp: RelyingParty(id: rpId, name: rpId),
            rpIDHash: AuthenticatorData.makeRpIdHash(rpId),
            totalRPs: rps.count
        )
    }

    private func enumerateRPsGetNext() throws -> CredentialManagementResponse {
        guard let rps = rpEnumeration, rpEnumIndex < rps.count else {
            throw CTAPError.notAllowed
        }
        let rpId = rps[rpEnumIndex]
        rpEnumIndex += 1
        return CredentialManagementResponse(
            rp: RelyingParty(id: rpId, name: rpId),
            rpIDHash: AuthenticatorData.makeRpIdHash(rpId)
        )
    }

    private func enumerateCredentialsBegin(params: CBORValue?) async throws -> CredentialManagementResponse {
        guard let params = params, case .map(let pairs) = params else {
            throw CTAPError.invalidParameter
        }
        var rpIdHash: Data?
        for (key, value) in pairs {
            if case .unsignedInt(0x01) = key, case .byteString(let hash) = value {
                rpIdHash = hash
            }
        }
        guard let hash = rpIdHash else { throw CTAPError.invalidParameter }

        let rps = try await store.enumerateRelyingParties()
        guard let rpId = rps.first(where: { AuthenticatorData.makeRpIdHash($0) == hash }) else {
            throw CTAPError.noCredentials
        }

        let creds = try await store.findAll(relyingPartyId: rpId)
        guard !creds.isEmpty else {
            throw CTAPError.noCredentials
        }
        credEnumeration = creds
        credEnumIndex = 1

        let cred = creds[0]
        return CredentialManagementResponse(
            user: PublicKeyUser(id: cred.userId, name: cred.userName, displayName: cred.userDisplayName),
            credentialID: PublicKeyCredentialDescriptor(id: cred.credentialId),
            totalCredentials: creds.count,
            credProtect: cred.credProtect,
            largeBlobKey: cred.largeBlobKey
        )
    }

    private func enumerateCredentialsGetNext() throws -> CredentialManagementResponse {
        guard let creds = credEnumeration, credEnumIndex < creds.count else {
            throw CTAPError.notAllowed
        }
        let cred = creds[credEnumIndex]
        credEnumIndex += 1
        return CredentialManagementResponse(
            user: PublicKeyUser(id: cred.userId, name: cred.userName, displayName: cred.userDisplayName),
            credentialID: PublicKeyCredentialDescriptor(id: cred.credentialId),
            credProtect: cred.credProtect,
            largeBlobKey: cred.largeBlobKey
        )
    }

    private func deleteCredential(params: CBORValue?) async throws -> CredentialManagementResponse {
        guard let params = params, case .map(let pairs) = params else {
            throw CTAPError.invalidParameter
        }
        var credId: Data?
        for (key, value) in pairs {
            if case .unsignedInt(0x02) = key, case .map(let descPairs) = value {
                for (dk, dv) in descPairs {
                    if case .textString("id") = dk, case .byteString(let id) = dv {
                        credId = id
                    }
                }
            }
        }
        guard let id = credId else { throw CTAPError.invalidParameter }
        try await store.delete(credentialId: id)
        // Invalidate any ongoing enumeration
        rpEnumeration = nil
        credEnumeration = nil
        return CredentialManagementResponse()
    }

    private func updateUserInformation(params: CBORValue?) async throws -> CredentialManagementResponse {
        guard let params = params, case .map(let pairs) = params else {
            throw CTAPError.invalidParameter
        }
        var credId: Data?
        var userName: String?
        var userDisplayName: String?

        for (key, value) in pairs {
            if case .unsignedInt(0x02) = key, case .map(let descPairs) = value {
                for (dk, dv) in descPairs {
                    if case .textString("id") = dk, case .byteString(let id) = dv { credId = id }
                }
            }
            if case .unsignedInt(0x03) = key, case .map(let userPairs) = value {
                for (uk, uv) in userPairs {
                    if case .textString("name") = uk, case .textString(let n) = uv { userName = n }
                    if case .textString("displayName") = uk, case .textString(let d) = uv { userDisplayName = d }
                }
            }
        }

        guard let id = credId else { throw CTAPError.invalidParameter }
        try await store.update(
            credentialId: id,
            userName: userName ?? "",
            userDisplayName: userDisplayName ?? ""
        )
        return CredentialManagementResponse()
    }
}

public enum CTAPError: Error, Sendable {
    case noCredentials
    case notAllowed
    case invalidParameter
    case storageFull
}
