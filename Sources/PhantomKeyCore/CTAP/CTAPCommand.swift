import Foundation

public enum CTAPCommandType: UInt8, Sendable {
    case makeCredential = 0x01
    case getAssertion = 0x02
    case getInfo = 0x04
    case clientPIN = 0x06
    case reset = 0x07
    case selection = 0x0B
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
    case noCredentials = 0x2E
    case userActionTimeout = 0x2F
    case notAllowed = 0x30
    case pinInvalid = 0x31
    case upRequired = 0x35
    case keepAliveCancel = 0x2D
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
