#if targetEnvironment(simulator)
import Foundation
import CryptoKit
import PhantomKeyCore
import os.log

private let logger = Logger(subsystem: "md.thomas.phantomkey.ios", category: "SigningServer")

/// TCP signing server for simulator testing.
/// Listens on localhost:7878, accepts CTAP requests, signs with SimulatorKeyStore.
/// Simple in-memory credential store that preserves the exact key material provided.
private actor DirectCredentialStore {
    private var credentials: [StoredCredential] = []

    func store(credential: StoredCredential) {
        credentials.append(credential)
    }

    func find(credentialId: Data) -> StoredCredential? {
        credentials.first { $0.credentialId == credentialId }
    }

    func find(relyingPartyId: String) -> [StoredCredential] {
        credentials.filter { $0.relyingPartyId == relyingPartyId }
    }

    func findAny(credentialId: Data) -> StoredCredential? {
        credentials.first { $0.credentialId == credentialId }
    }

    func enumerateRelyingParties() -> [String] {
        Array(Set(credentials.map(\.relyingPartyId)))
    }
}

actor LoopbackSigningServer {
    private let port: UInt16
    private let keyStore = DirectCredentialStore()
    private var serverFD: Int32 = -1
    private var running = false
    private var listenTask: Task<Void, Never>?

    init(port: UInt16 = LoopbackSigningService.defaultPort) {
        self.port = port
    }

    func start() throws {
        guard !running else { return }

        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return }

        var reuse: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")

        let bindResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                bind(fd, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0 else {
            close(fd)
            return
        }

        guard listen(fd, 5) == 0 else {
            close(fd)
            return
        }

        serverFD = fd
        running = true

        let p = port
        logger.info("[LoopbackSigningServer] Listening on 127.0.0.1:\(p, privacy: .public)")

        listenTask = Task { [weak self] in
            await self?.acceptLoop()
        }
    }

    func stop() {
        running = false
        listenTask?.cancel()
        if serverFD >= 0 {
            close(serverFD)
            serverFD = -1
        }
    }

    private func acceptLoop() async {
        let fd = serverFD
        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)

        while running && !Task.isCancelled {
            var clientAddr = sockaddr_in()
            var addrLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            let clientFD = withUnsafeMutablePointer(to: &clientAddr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                    accept(fd, sockaddrPtr, &addrLen)
                }
            }

            if clientFD >= 0 {
                logger.info("[LoopbackSigningServer] Client connected")
                let store = keyStore
                Task.detached {
                    await Self.handleClient(clientFD, keyStore: store)
                }
            } else if errno == EWOULDBLOCK || errno == EAGAIN {
                try? await Task.sleep(nanoseconds: 50_000_000)
            } else {
                break
            }
        }
    }

    private static func handleClient(_ fd: Int32, keyStore: DirectCredentialStore) async {
        defer { close(fd) }

        // Set blocking
        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags & ~O_NONBLOCK)

        while true {
            guard let envelope = try? LoopbackSigningService.receiveMessage(fd) else {
                break
            }

            logger.info("[LoopbackSigningServer] Received \(String(describing: envelope.type), privacy: .public)")

            do {
                let response: Envelope
                switch envelope.type {
                case .makeCredentialRequest:
                    response = try await handleMakeCredential(envelope, keyStore: keyStore)
                case .getAssertionRequest:
                    response = try await handleGetAssertion(envelope, keyStore: keyStore)
                case .directSignRequest:
                    response = try await handleDirectSign(envelope, keyStore: keyStore)
                case .getInfoRequest:
                    let info = AuthenticatorInfo.phantomKey
                    let payload = CBOREncoder().encode(info.toCBOR())
                    response = Envelope(type: .getInfoResponse, sequence: 0, payload: payload)
                default:
                    response = Envelope(type: .error, sequence: 0, payload: Data())
                }
                try LoopbackSigningService.sendMessage(fd, envelope: response)
            } catch {
                logger.info("[LoopbackSigningServer] Error: \(error.localizedDescription, privacy: .public)")
                let errResponse = Envelope(type: .error, sequence: 0, payload: Data())
                try? LoopbackSigningService.sendMessage(fd, envelope: errResponse)
            }
        }

        logger.info("[LoopbackSigningServer] Client disconnected")
    }

    // MARK: - CTAP Handlers

    private static func handleMakeCredential(_ envelope: Envelope, keyStore: DirectCredentialStore) async throws -> Envelope {
        let decoded = try CBORDecoder().decode(envelope.payload)
        guard case .map(let pairs) = decoded else { throw AuthenticatorError.invalidRequest }

        let clientDataHashEntry = pairs.first { $0.0 == .unsignedInt(1) }
        guard case .byteString(let clientDataHash) = clientDataHashEntry?.1 else {
            throw AuthenticatorError.invalidRequest
        }

        let rpEntry = pairs.first { $0.0 == .unsignedInt(2) }
        guard case .map(let rpPairs) = rpEntry?.1 else { throw AuthenticatorError.invalidRequest }
        let rpIdEntry = rpPairs.first { $0.0 == .textString("id") }
        guard case .textString(let rpId) = rpIdEntry?.1 else { throw AuthenticatorError.invalidRequest }
        let rpNameEntry = rpPairs.first { $0.0 == .textString("name") }
        let rpName: String
        if case .textString(let name) = rpNameEntry?.1 { rpName = name } else { rpName = rpId }

        let userEntry = pairs.first { $0.0 == .unsignedInt(3) }
        guard case .map(let userPairs) = userEntry?.1 else { throw AuthenticatorError.invalidRequest }
        let userIdEntry = userPairs.first { $0.0 == .textString("id") }
        guard case .byteString(let userId) = userIdEntry?.1 else { throw AuthenticatorError.invalidRequest }
        let userNameEntry = userPairs.first { $0.0 == .textString("name") }
        let userName: String
        if case .textString(let name) = userNameEntry?.1 { userName = name } else { userName = "unknown" }
        let displayNameEntry = userPairs.first { $0.0 == .textString("displayName") }
        let displayName: String
        if case .textString(let name) = displayNameEntry?.1 { displayName = name } else { displayName = userName }

        // Generate credential
        let keyPair = SoftwareKeyPair.generate(algorithm: .es256)
        let credential = StoredCredential(
            credentialId: keyPair.credentialId,
            relyingPartyId: rpId,
            relyingPartyName: rpName,
            userId: userId,
            userName: userName,
            userDisplayName: displayName,
            privateKeySerialized: keyPair.privateKeyData,
            algorithm: KeyAlgorithm.es256.rawValue,
            createdAt: Date(),
            isResident: true,
            signatureCounter: 0,
            credProtect: nil,
            largeBlobKey: nil,
            hmacSecret: nil
        )
        await keyStore.store(credential: credential)

        // Build authenticator data with attested credential
        let rpIdHash = AuthenticatorData.makeRpIdHash(rpId)
        let aaguid = Data("PhantomKeySim\0\0\0".utf8.prefix(16))
        let publicKeyCOSE = CBOREncoder().encode(keyPair.publicKeyCOSE())
        let attestedCredData = AttestationBuilder().buildAttestedCredentialData(
            aaguid: aaguid,
            credentialId: keyPair.credentialId,
            publicKeyCOSE: publicKeyCOSE
        )
        let flags: UInt8 = AuthenticatorData.flagUserPresent
            | AuthenticatorData.flagUserVerified
            | AuthenticatorData.flagAttestedCredential
        let authData = AuthenticatorData(
            rpIdHash: rpIdHash,
            flags: flags,
            signCount: 1,
            attestedCredentialData: attestedCredData
        )
        let authDataBytes = authData.serialize()

        let attestationObject = try AttestationBuilder().buildSelfAttestation(
            authData: authDataBytes,
            clientDataHash: clientDataHash,
            keyPair: keyPair
        )

        let responsePayload = CBOREncoder().encode(.map([
            (.unsignedInt(1), .byteString(attestationObject)),
            (.unsignedInt(2), .byteString(keyPair.credentialId)),
        ]))

        logger.info("[LoopbackSigningServer] Created credential for \(rpId, privacy: .public)")
        return Envelope(type: .makeCredentialResponse, sequence: 0, payload: responsePayload)
    }

    private static func handleGetAssertion(_ envelope: Envelope, keyStore: DirectCredentialStore) async throws -> Envelope {
        let decoded = try CBORDecoder().decode(envelope.payload)
        guard case .map(let pairs) = decoded else { throw AuthenticatorError.invalidRequest }

        let rpIdEntry = pairs.first { $0.0 == .unsignedInt(1) }
        guard case .textString(let rpId) = rpIdEntry?.1 else { throw AuthenticatorError.invalidRequest }

        let clientDataHashEntry = pairs.first { $0.0 == .unsignedInt(2) }
        guard case .byteString(let clientDataHash) = clientDataHashEntry?.1 else {
            throw AuthenticatorError.invalidRequest
        }

        // Find credential by allowList
        var credentialId: Data?
        let allowListEntry = pairs.first { $0.0 == .unsignedInt(3) }
        if case .array(let allowList) = allowListEntry?.1 {
            for item in allowList {
                if case .map(let itemPairs) = item,
                   let idEntry = itemPairs.first(where: { $0.0 == .textString("id") }),
                   case .byteString(let id) = idEntry.1 {
                    credentialId = id
                    break
                }
            }
        }

        let credentials: [StoredCredential]
        if let credentialId {
            // Find by credential ID, then verify RP ID matches
            let found = [await keyStore.findAny(credentialId: credentialId)].compactMap { $0 }
            credentials = found.filter { $0.relyingPartyId == rpId }
        } else {
            credentials = await keyStore.find(relyingPartyId: rpId)
        }
        guard let cred = credentials.first else {
            throw AuthenticatorError.credentialNotFound
        }

        // Sign
        let rpIdHash = AuthenticatorData.makeRpIdHash(rpId)
        let assertFlags: UInt8 = AuthenticatorData.flagUserPresent | AuthenticatorData.flagUserVerified
        let assertAuthData = AuthenticatorData(
            rpIdHash: rpIdHash,
            flags: assertFlags,
            signCount: cred.signatureCounter + 1
        )
        let authDataBytes = assertAuthData.serialize()

        var signBase = Data()
        signBase.append(authDataBytes)
        signBase.append(clientDataHash)

        let privateKey = try P256.Signing.PrivateKey(rawRepresentation: cred.privateKeySerialized)
        let signature = try privateKey.signature(for: signBase)

        let responsePayload = CBOREncoder().encode(.map([
            (.unsignedInt(1), .byteString(cred.credentialId)),
            (.unsignedInt(2), .byteString(authDataBytes)),
            (.unsignedInt(3), .byteString(signature.derRepresentation)),
            (.unsignedInt(4), .byteString(cred.userId)),
        ]))

        logger.info("[LoopbackSigningServer] Signed assertion for \(rpId, privacy: .public)")
        return Envelope(type: .getAssertionResponse, sequence: 0, payload: responsePayload)
    }

    private static func handleDirectSign(_ envelope: Envelope, keyStore: DirectCredentialStore) async throws -> Envelope {
        let decoded = try CBORDecoder().decode(envelope.payload)
        guard case .map(let pairs) = decoded else { throw AuthenticatorError.invalidRequest }

        let credIdEntry = pairs.first { $0.0 == .unsignedInt(1) }
        guard case .byteString(let credentialId) = credIdEntry?.1 else {
            throw AuthenticatorError.invalidRequest
        }

        let dataEntry = pairs.first { $0.0 == .unsignedInt(2) }
        guard case .byteString(let dataToSign) = dataEntry?.1 else {
            throw AuthenticatorError.invalidRequest
        }

        guard let cred = await keyStore.findAny(credentialId: credentialId) else {
            throw AuthenticatorError.credentialNotFound
        }

        let privateKey = try P256.Signing.PrivateKey(rawRepresentation: cred.privateKeySerialized)
        let signature = try privateKey.signature(for: dataToSign)

        let responsePayload = CBOREncoder().encode(.map([
            (.unsignedInt(1), .byteString(signature.derRepresentation)),
        ]))

        logger.info("[LoopbackSigningServer] Direct-signed \(dataToSign.count, privacy: .public) bytes")
        return Envelope(type: .directSignResponse, sequence: 0, payload: responsePayload)
    }
}
#endif
