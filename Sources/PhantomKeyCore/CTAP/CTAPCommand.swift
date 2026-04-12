import Foundation

public enum CTAPCommandType: UInt8, Sendable {
    case makeCredential = 0x01
    case getAssertion = 0x02
    case getNextAssertion = 0x08
    case getInfo = 0x04
    case clientPIN = 0x06
    case reset = 0x07
    case credentialManagement = 0x0A
    case selection = 0x0B
    case largeBlobStore = 0x0C
}

public enum CTAPStatusCode: UInt8, Sendable {
    case ok = 0x00
    case invalidCommand = 0x01
    case invalidParameter = 0x02
    case invalidLength = 0x03
    case invalidSeq = 0x04
    case timeout = 0x05
    case channelBusy = 0x06
    case lockRequired = 0x0A
    case invalidChannel = 0x0B
    case operationDenied = 0x27
    case keyStoreFull = 0x28
    case keepAliveCancel = 0x2D
    case noCredentials = 0x2E
    case userActionTimeout = 0x2F
    case notAllowed = 0x30
    case pinInvalid = 0x31
    case pinBlocked = 0x32
    case pinAuthInvalid = 0x33
    case pinAuthBlocked = 0x34
    case pinNotSet = 0x35
    case puatRequired = 0x36
    case pinPolicyViolation = 0x37
    case requestTooLarge = 0x39
    case actionTimeout = 0x3A
    case uvBlocked = 0x3C
    case integrityFailure = 0x3D
    case invalidSubcommand = 0x3E
    case uvInvalid = 0x3F
    case unauthorizedPermission = 0x40
    case largeBlobStorageFull = 0x42
}

// MARK: - CTAP 2.1 Credential Protection

public enum CredentialProtectionLevel: UInt8, Sendable, Codable {
    case userVerificationOptional = 0x01
    case userVerificationOptionalWithCredentialIDList = 0x02
    case userVerificationRequired = 0x03
}

// MARK: - CTAP 2.1 Credential Management

public enum CredentialManagementSubCommand: UInt8, Sendable {
    case getCredsMetadata = 0x01
    case enumerateRPsBegin = 0x02
    case enumerateRPsGetNextRP = 0x03
    case enumerateCredentialsBegin = 0x04
    case enumerateCredentialsGetNextCredential = 0x05
    case deleteCredential = 0x06
    case updateUserInformation = 0x07
}

public struct CredentialManagementRequest: Sendable {
    public let subCommand: CredentialManagementSubCommand
    public let subCommandParams: CBORValue?
    public let pinUvAuthProtocol: Int?
    public let pinUvAuthParam: Data?

    public init(
        subCommand: CredentialManagementSubCommand,
        subCommandParams: CBORValue? = nil,
        pinUvAuthProtocol: Int? = nil,
        pinUvAuthParam: Data? = nil
    ) {
        self.subCommand = subCommand
        self.subCommandParams = subCommandParams
        self.pinUvAuthProtocol = pinUvAuthProtocol
        self.pinUvAuthParam = pinUvAuthParam
    }
}

public struct CredentialManagementResponse: Sendable {
    public let existingResidentCredentialsCount: Int?
    public let maxPossibleRemainingResidentCredentialsCount: Int?
    public let rp: RelyingParty?
    public let rpIDHash: Data?
    public let totalRPs: Int?
    public let user: PublicKeyUser?
    public let credentialID: PublicKeyCredentialDescriptor?
    public let publicKey: CBORValue?
    public let totalCredentials: Int?
    public let credProtect: UInt8?
    public let largeBlobKey: Data?

    public init(
        existingResidentCredentialsCount: Int? = nil,
        maxPossibleRemainingResidentCredentialsCount: Int? = nil,
        rp: RelyingParty? = nil,
        rpIDHash: Data? = nil,
        totalRPs: Int? = nil,
        user: PublicKeyUser? = nil,
        credentialID: PublicKeyCredentialDescriptor? = nil,
        publicKey: CBORValue? = nil,
        totalCredentials: Int? = nil,
        credProtect: UInt8? = nil,
        largeBlobKey: Data? = nil
    ) {
        self.existingResidentCredentialsCount = existingResidentCredentialsCount
        self.maxPossibleRemainingResidentCredentialsCount = maxPossibleRemainingResidentCredentialsCount
        self.rp = rp
        self.rpIDHash = rpIDHash
        self.totalRPs = totalRPs
        self.user = user
        self.credentialID = credentialID
        self.publicKey = publicKey
        self.totalCredentials = totalCredentials
        self.credProtect = credProtect
        self.largeBlobKey = largeBlobKey
    }
}

// MARK: - CTAP 2.1 Large Blob

public struct LargeBlobRequest: Sendable {
    public let get: Int?
    public let set: Data?
    public let offset: Int
    public let length: Int?
    public let pinUvAuthParam: Data?
    public let pinUvAuthProtocol: Int?

    public init(
        get: Int? = nil,
        set: Data? = nil,
        offset: Int = 0,
        length: Int? = nil,
        pinUvAuthParam: Data? = nil,
        pinUvAuthProtocol: Int? = nil
    ) {
        self.get = get
        self.set = set
        self.offset = offset
        self.length = length
        self.pinUvAuthParam = pinUvAuthParam
        self.pinUvAuthProtocol = pinUvAuthProtocol
    }
}

// MARK: - CTAP 2.1 HMAC-Secret

public struct HMACSecretInput: Sendable {
    public let keyAgreement: CBORValue
    public let saltEnc: Data
    public let saltAuth: Data
    public let pinUvAuthProtocol: Int

    public init(keyAgreement: CBORValue, saltEnc: Data, saltAuth: Data, pinUvAuthProtocol: Int) {
        self.keyAgreement = keyAgreement
        self.saltEnc = saltEnc
        self.saltAuth = saltAuth
        self.pinUvAuthProtocol = pinUvAuthProtocol
    }
}

public struct MakeCredentialRequest: Sendable {
    public let clientDataHash: Data
    public let relyingParty: RelyingParty
    public let user: PublicKeyUser
    public let pubKeyCredParams: [PublicKeyCredParam]
    public let excludeList: [PublicKeyCredentialDescriptor]
    public let requireResidentKey: Bool
    public let requireUserVerification: Bool

    public init(
        clientDataHash: Data,
        relyingParty: RelyingParty,
        user: PublicKeyUser,
        pubKeyCredParams: [PublicKeyCredParam],
        excludeList: [PublicKeyCredentialDescriptor] = [],
        requireResidentKey: Bool = false,
        requireUserVerification: Bool = false
    ) {
        self.clientDataHash = clientDataHash
        self.relyingParty = relyingParty
        self.user = user
        self.pubKeyCredParams = pubKeyCredParams
        self.excludeList = excludeList
        self.requireResidentKey = requireResidentKey
        self.requireUserVerification = requireUserVerification
    }
}

public struct GetAssertionRequest: Sendable {
    public let relyingPartyId: String
    public let clientDataHash: Data
    public let allowList: [PublicKeyCredentialDescriptor]
    public let requireUserVerification: Bool

    public init(
        relyingPartyId: String,
        clientDataHash: Data,
        allowList: [PublicKeyCredentialDescriptor] = [],
        requireUserVerification: Bool = false
    ) {
        self.relyingPartyId = relyingPartyId
        self.clientDataHash = clientDataHash
        self.allowList = allowList
        self.requireUserVerification = requireUserVerification
    }
}

public struct RelyingParty: Sendable, Codable {
    public let id: String
    public let name: String

    public init(id: String, name: String) {
        self.id = id
        self.name = name
    }
}

public struct PublicKeyUser: Sendable, Codable {
    public let id: Data
    public let name: String
    public let displayName: String

    public init(id: Data, name: String, displayName: String) {
        self.id = id
        self.name = name
        self.displayName = displayName
    }
}

public struct PublicKeyCredParam: Sendable {
    public let type: String
    public let algorithm: Int

    public static let es256 = PublicKeyCredParam(type: "public-key", algorithm: -7)
    public static let edDSA = PublicKeyCredParam(type: "public-key", algorithm: -8)

    public init(type: String, algorithm: Int) {
        self.type = type
        self.algorithm = algorithm
    }
}

public struct PublicKeyCredentialDescriptor: Sendable {
    public let type: String
    public let id: Data
    public let transports: [String]

    public init(type: String = "public-key", id: Data, transports: [String] = []) {
        self.type = type
        self.id = id
        self.transports = transports
    }
}

public struct MakeCredentialResponse: Sendable {
    public let attestationObject: Data
    public let credentialId: Data

    public init(attestationObject: Data, credentialId: Data) {
        self.attestationObject = attestationObject
        self.credentialId = credentialId
    }
}

public struct GetAssertionResponse: Sendable {
    public let credentialId: Data
    public let authenticatorData: Data
    public let signature: Data
    public let userHandle: Data?

    public init(credentialId: Data, authenticatorData: Data, signature: Data, userHandle: Data?) {
        self.credentialId = credentialId
        self.authenticatorData = authenticatorData
        self.signature = signature
        self.userHandle = userHandle
    }
}
