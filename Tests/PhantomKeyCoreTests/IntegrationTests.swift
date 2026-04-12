import Testing
import Foundation
import Crypto
@testable import PhantomKeyCore

// MARK: - PipeTransportChannel

/// In-memory transport channel that connects two sides via async streams.
/// Use `makePipeChannelPair()` to create a cross-linked pair.
/// Wraps an `AsyncStream<Data>.Iterator` so it can be used inside an actor
/// (the iterator is mutated exclusively through this class).
private final class StreamIterator: @unchecked Sendable {
    var iterator: AsyncStream<Data>.Iterator

    init(_ iterator: AsyncStream<Data>.Iterator) {
        self.iterator = iterator
    }

    func next() async -> Data? {
        await iterator.next()
    }
}

actor PipeTransportChannel: TransportChannel {
    private var connected = true
    private let inboundContinuation: AsyncStream<Data>.Continuation
    private var outboundContinuation: AsyncStream<Data>.Continuation?
    private let streamIterator: StreamIterator

    init() {
        let (stream, continuation) = AsyncStream<Data>.makeStream()
        self.inboundContinuation = continuation
        self.streamIterator = StreamIterator(stream.makeAsyncIterator())
    }

    /// Link this channel's outbound to the peer's inbound.
    func linkOutbound(_ peer: AsyncStream<Data>.Continuation) {
        self.outboundContinuation = peer
    }

    /// Expose this channel's inbound continuation so the peer can send to us.
    nonisolated var inboundSink: AsyncStream<Data>.Continuation {
        // Safe because inboundContinuation is set once in init and never mutated.
        inboundContinuation
    }

    var isConnected: Bool { connected }

    func send(_ data: Data) async throws {
        guard connected else { throw TransportError.notConnected }
        guard let out = outboundContinuation else { throw TransportError.sendFailed("not linked") }
        out.yield(data)
    }

    func receive() async throws -> Data {
        guard connected else { throw TransportError.notConnected }
        guard let data = await streamIterator.next() else {
            throw TransportError.peerDisconnected
        }
        return data
    }

    func disconnect() async {
        connected = false
        inboundContinuation.finish()
    }
}

/// Create a cross-linked pair of in-memory transport channels.
/// Side A's `send()` delivers to side B's `receive()` and vice versa.
func makePipeChannelPair() async -> (PipeTransportChannel, PipeTransportChannel) {
    let a = PipeTransportChannel()
    let b = PipeTransportChannel()
    // A sends to B's inbound, B sends to A's inbound
    await a.linkOutbound(b.inboundSink)
    await b.linkOutbound(a.inboundSink)
    return (a, b)
}

// MARK: - Integration Tests

@Suite("End-to-end integration")
struct IntegrationTests {

    @Test("Full signing flow: pairing, Noise NK, secure channel, getInfo, makeCredential, getAssertion")
    func testFullSigningFlow() async throws {

        // =====================================================================
        // (a) Pairing: Mac (initiator) and iPhone (responder) derive shared secret
        // =====================================================================

        let initiator = PairingInitiator()
        let responder = PairingResponder()

        let qrData = initiator.qrData

        let macPaired = try initiator.completePairing(
            remotePublicKey: responder.publicKeyData,
            deviceId: "iphone-001",
            deviceName: "Test iPhone"
        )
        let iphonePaired = try responder.completePairing(
            scannedData: qrData,
            deviceId: "mac-001"
        )

        #expect(macPaired.sharedSecret == iphonePaired.sharedSecret,
                "Pairing shared secrets must match")

        // =====================================================================
        // (b) Noise NK Handshake
        // =====================================================================

        // Mac initiates using the responder's (iPhone's) static public key
        var (handshakeMsg, pending) = try NoiseNK.initiator(
            responderStaticPublic: responder.publicKeyData
        )

        // iPhone processes the handshake message
        let (handshakeResponse, responderSendCipher, responderReceiveCipher) =
            try NoiseNK.responder(
                staticPrivateKey: responder.staticPrivateKey,
                message: handshakeMsg
            )

        // Mac finalizes
        let (initiatorSendCipher, initiatorReceiveCipher) =
            try NoiseNK.initiatorFinalize(
                pendingEphemeralPrivate: pending.ephemeralPrivate,
                symmetricState: &pending.symmetricState,
                responseMessage: handshakeResponse
            )

        // Verify cipher state cross-assignment:
        // Initiator's sendCipher encrypts what responder's receiveCipher decrypts
        // and vice versa. We prove this by running the full channel below.

        // =====================================================================
        // (c) Secure Channel Setup over PipeTransportChannel
        // =====================================================================

        let (macTransport, iphoneTransport) = await makePipeChannelPair()

        let macChannel = SecureChannel(
            transport: macTransport,
            sendCipher: initiatorSendCipher,
            receiveCipher: initiatorReceiveCipher
        )
        let iphoneChannel = SecureChannel(
            transport: iphoneTransport,
            sendCipher: responderSendCipher,
            receiveCipher: responderReceiveCipher
        )

        // =====================================================================
        // (d) GetInfo Request / Response
        // =====================================================================

        // Mac sends getInfoRequest, iPhone receives and replies
        async let getInfoResponseEnvelope: Envelope = macChannel.receive()

        // iPhone side: receive request, build response, send it back
        let getInfoTask = Task {
            let request = try await iphoneChannel.receive()
            #expect(request.type == .getInfoRequest)

            let info = AuthenticatorInfo.phantomKey
            let infoCBOR = info.toCBOR()
            let infoData = CBOREncoder().encode(infoCBOR)

            try await iphoneChannel.send(type: .getInfoResponse, payload: infoData)
        }

        // Mac sends request
        try await macChannel.send(type: .getInfoRequest, payload: Data())

        // Wait for iPhone to process
        try await getInfoTask.value

        // Mac receives response
        let infoEnvelope = try await getInfoResponseEnvelope
        #expect(infoEnvelope.type == .getInfoResponse)

        // Decode and verify
        let decodedInfo = try CBORDecoder().decode(infoEnvelope.payload)
        if case .map(let pairs) = decodedInfo {
            // Find versions (key 0x01)
            let versionsEntry = pairs.first { $0.0 == .unsignedInt(0x01) }
            if case .array(let versions) = versionsEntry?.1 {
                let versionStrings = versions.compactMap { val -> String? in
                    if case .textString(let s) = val { return s }
                    return nil
                }
                #expect(versionStrings.contains("FIDO_2_1"),
                        "AuthenticatorInfo must contain FIDO_2_1")
            } else {
                Issue.record("versions field missing or wrong type")
            }
        } else {
            Issue.record("getInfoResponse payload is not a CBOR map")
        }

        // =====================================================================
        // (e) MakeCredential flow
        // =====================================================================

        let rpId = "example.com"
        let rpName = "Example Corp"
        let rpIdHash = AuthenticatorData.makeRpIdHash(rpId)
        let clientDataHash = Data(SHA256.hash(data: Data("test-client-data".utf8)))
        let aaguid = Data(repeating: 0xAA, count: 16)

        // iPhone-side credential key pair
        let credentialKeyPair = SoftwareKeyPair.generate(algorithm: .es256)

        // Build the MakeCredential request payload as CBOR
        let makeCredPayload = CBOREncoder().encode(.map([
            (.unsignedInt(1), .byteString(clientDataHash)),                       // clientDataHash
            (.unsignedInt(2), .map([                                              // rp
                (.textString("id"), .textString(rpId)),
                (.textString("name"), .textString(rpName)),
            ])),
            (.unsignedInt(3), .map([                                              // user
                (.textString("id"), .byteString(Data("user-123".utf8))),
                (.textString("name"), .textString("alice@example.com")),
                (.textString("displayName"), .textString("Alice")),
            ])),
            (.unsignedInt(4), .array([                                            // pubKeyCredParams
                .map([
                    (.textString("type"), .textString("public-key")),
                    (.textString("alg"), .negativeInt(-7)),
                ]),
            ])),
        ]))

        // Send from Mac, receive on iPhone, build attestation, reply
        async let makeCredResponseEnvelope: Envelope = macChannel.receive()

        let makeCredTask = Task {
            let request = try await iphoneChannel.receive()
            #expect(request.type == .makeCredentialRequest)

            // Build attested credential data
            let publicKeyCOSE = CBOREncoder().encode(credentialKeyPair.publicKeyCOSE())
            let attestedCredData = AttestationBuilder().buildAttestedCredentialData(
                aaguid: aaguid,
                credentialId: credentialKeyPair.credentialId,
                publicKeyCOSE: publicKeyCOSE
            )

            // Build authenticator data with UP + UV + AT flags
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

            // Build self-attestation
            let attestationObject = try AttestationBuilder().buildSelfAttestation(
                authData: authDataBytes,
                clientDataHash: clientDataHash,
                keyPair: credentialKeyPair
            )

            // Encode response as CBOR map
            let responsePayload = CBOREncoder().encode(.map([
                (.unsignedInt(1), .byteString(attestationObject)),
                (.unsignedInt(2), .byteString(credentialKeyPair.credentialId)),
            ]))

            try await iphoneChannel.send(type: .makeCredentialResponse, payload: responsePayload)
        }

        try await macChannel.send(type: .makeCredentialRequest, payload: makeCredPayload)
        try await makeCredTask.value

        let credEnvelope = try await makeCredResponseEnvelope
        #expect(credEnvelope.type == .makeCredentialResponse)

        // Parse the response and verify attestation
        let credResponse = try CBORDecoder().decode(credEnvelope.payload)
        guard case .map(let credPairs) = credResponse else {
            Issue.record("makeCredentialResponse payload is not a CBOR map")
            return
        }

        let attestationEntry = credPairs.first { $0.0 == .unsignedInt(1) }
        guard case .byteString(let attestationObjData) = attestationEntry?.1 else {
            Issue.record("attestation object missing")
            return
        }

        // Decode attestation object, verify fmt=packed and sig is valid
        let attObj = try CBORDecoder().decode(attestationObjData)
        guard case .map(let attPairs) = attObj else {
            Issue.record("attestation object is not a CBOR map")
            return
        }

        let fmtEntry = attPairs.first { $0.0 == .textString("fmt") }
        #expect(fmtEntry?.1 == .textString("packed"), "Attestation format must be packed")

        let authDataEntry = attPairs.first { $0.0 == .textString("authData") }
        guard case .byteString(let attestAuthData) = authDataEntry?.1 else {
            Issue.record("authData missing from attestation object")
            return
        }

        let attStmtEntry = attPairs.first { $0.0 == .textString("attStmt") }
        guard case .map(let stmtPairs) = attStmtEntry?.1 else {
            Issue.record("attStmt missing")
            return
        }

        let sigEntry = stmtPairs.first { $0.0 == .textString("sig") }
        guard case .byteString(let attestSig) = sigEntry?.1 else {
            Issue.record("sig missing from attStmt")
            return
        }

        // Verify self-attestation signature: sign(authData || clientDataHash)
        var signatureBase = Data()
        signatureBase.append(attestAuthData)
        signatureBase.append(clientDataHash)

        let attestVerified = try credentialKeyPair.verify(signature: attestSig, for: signatureBase)
        #expect(attestVerified, "Self-attestation signature must verify")

        // =====================================================================
        // (f) GetAssertion flow
        // =====================================================================

        let assertionClientDataHash = Data(SHA256.hash(data: Data("assertion-client-data".utf8)))

        let getAssertionPayload = CBOREncoder().encode(.map([
            (.unsignedInt(1), .textString(rpId)),                                     // rpId
            (.unsignedInt(2), .byteString(assertionClientDataHash)),                  // clientDataHash
            (.unsignedInt(3), .array([                                                // allowList
                .map([
                    (.textString("type"), .textString("public-key")),
                    (.textString("id"), .byteString(credentialKeyPair.credentialId)),
                ]),
            ])),
        ]))

        async let assertionResponseEnvelope: Envelope = macChannel.receive()

        let assertionTask = Task {
            let request = try await iphoneChannel.receive()
            #expect(request.type == .getAssertionRequest)

            // Build authenticator data for assertion (no attested cred data, UP+UV)
            let assertFlags: UInt8 = AuthenticatorData.flagUserPresent
                | AuthenticatorData.flagUserVerified
            let assertAuthData = AuthenticatorData(
                rpIdHash: rpIdHash,
                flags: assertFlags,
                signCount: 2
            )
            let assertAuthDataBytes = assertAuthData.serialize()

            // Sign authData || clientDataHash
            var assertSignBase = Data()
            assertSignBase.append(assertAuthDataBytes)
            assertSignBase.append(assertionClientDataHash)
            let assertSig = try credentialKeyPair.sign(assertSignBase)

            // Build response as CBOR
            let assertResponsePayload = CBOREncoder().encode(.map([
                (.unsignedInt(1), .byteString(credentialKeyPair.credentialId)),    // credentialId
                (.unsignedInt(2), .byteString(assertAuthDataBytes)),               // authenticatorData
                (.unsignedInt(3), .byteString(assertSig)),                         // signature
                (.unsignedInt(4), .byteString(Data("user-123".utf8))),             // userHandle
            ]))

            try await iphoneChannel.send(type: .getAssertionResponse, payload: assertResponsePayload)
        }

        try await macChannel.send(type: .getAssertionRequest, payload: getAssertionPayload)
        try await assertionTask.value

        let assertEnvelope = try await assertionResponseEnvelope
        #expect(assertEnvelope.type == .getAssertionResponse)

        // Parse assertion response
        let assertResponse = try CBORDecoder().decode(assertEnvelope.payload)
        guard case .map(let assertPairs) = assertResponse else {
            Issue.record("getAssertionResponse payload is not a CBOR map")
            return
        }

        let assertCredIdEntry = assertPairs.first { $0.0 == .unsignedInt(1) }
        guard case .byteString(let returnedCredId) = assertCredIdEntry?.1 else {
            Issue.record("credentialId missing from assertion response")
            return
        }
        #expect(returnedCredId == credentialKeyPair.credentialId,
                "Returned credentialId must match")

        let assertAuthDataEntry = assertPairs.first { $0.0 == .unsignedInt(2) }
        guard case .byteString(let returnedAuthData) = assertAuthDataEntry?.1 else {
            Issue.record("authenticatorData missing from assertion response")
            return
        }

        let assertSigEntry = assertPairs.first { $0.0 == .unsignedInt(3) }
        guard case .byteString(let returnedSig) = assertSigEntry?.1 else {
            Issue.record("signature missing from assertion response")
            return
        }

        // Verify the assertion signature using the public key from makeCredential
        var assertVerifyBase = Data()
        assertVerifyBase.append(returnedAuthData)
        assertVerifyBase.append(assertionClientDataHash)

        // Verify using P256 public key directly (since we have the key pair)
        let assertionVerified = try credentialKeyPair.verify(signature: returnedSig, for: assertVerifyBase)
        #expect(assertionVerified, "Assertion signature must verify with credential public key")

        // Verify userHandle
        let userHandleEntry = assertPairs.first { $0.0 == .unsignedInt(4) }
        guard case .byteString(let userHandle) = userHandleEntry?.1 else {
            Issue.record("userHandle missing from assertion response")
            return
        }
        #expect(userHandle == Data("user-123".utf8), "userHandle must match")

        // Clean up
        await macChannel.disconnect()
        await iphoneChannel.disconnect()
    }
}
