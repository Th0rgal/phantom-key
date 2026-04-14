import Testing
import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
@testable import PhantomKeyCore

@Suite("SSH Agent")
struct SSHAgentTests {

    @Test("Agent starts and stops cleanly")
    func startStop() async throws {
        let path = NSTemporaryDirectory() + "pk-\(UInt32.random(in: 0...UInt32.max)).sock"
        let agent = SSHAgent(socketPath: path)
        try await agent.start()
        // Give the accept loop a moment to begin
        try await Task.sleep(nanoseconds: 100_000_000)

        // Socket file should exist
        #expect(FileManager.default.fileExists(atPath: path))

        await agent.stop()

        // Socket file should be cleaned up
        #expect(!FileManager.default.fileExists(atPath: path))
    }

    @Test("Agent responds to identity request via real socket")
    func identityRequest() async throws {
        let path = NSTemporaryDirectory() + "pk-\(UInt32.random(in: 0...UInt32.max)).sock"
        let agent = SSHAgent(socketPath: path)
        let key = SSHAgentKey.generate(comment: "test@phantomkey")
        await agent.addKey(key)
        try await agent.start()
        defer { Task { await agent.stop() } }

        // Connect to the agent socket
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        #expect(fd >= 0)
        defer { close(fd) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        path.utf8CString.withUnsafeBytes { pathBytes in
            withUnsafeMutableBytes(of: &addr.sun_path) { buf in
                let count = min(pathBytes.count, buf.count)
                buf.copyBytes(from: pathBytes.prefix(count))
            }
        }
        let connectResult = withUnsafePointer(to: &addr) { addrPtr in
            addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                connect(fd, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        #expect(connectResult == 0)

        // Send SSH_AGENTC_REQUEST_IDENTITIES
        let request = Data([11]) // message type only
        var reqLen = UInt32(request.count).bigEndian
        _ = write(fd, &reqLen, 4)
        _ = request.withUnsafeBytes { write(fd, $0.baseAddress!, $0.count) }

        // Read response length
        var respLenBuf = [UInt8](repeating: 0, count: 4)
        #expect(read(fd, &respLenBuf, 4) == 4)
        let respLen = Int(UInt32(respLenBuf[0]) << 24 | UInt32(respLenBuf[1]) << 16
            | UInt32(respLenBuf[2]) << 8 | UInt32(respLenBuf[3]))
        #expect(respLen > 0)

        // Read response body
        var respBuf = [UInt8](repeating: 0, count: respLen)
        var totalRead = 0
        while totalRead < respLen {
            let n = read(fd, &respBuf[totalRead], respLen - totalRead)
            #expect(n > 0)
            totalRead += n
        }
        let response = Data(respBuf)

        // Response should be SSH_AGENT_IDENTITIES_ANSWER (12)
        #expect(response[0] == 12)
        // Number of keys = 1
        let nkeys = UInt32(response[1]) << 24 | UInt32(response[2]) << 16
            | UInt32(response[3]) << 8 | UInt32(response[4])
        #expect(nkeys == 1)
    }

    @Test("Agent signs data correctly via real socket")
    func signRequest() async throws {
        let path = NSTemporaryDirectory() + "pk-\(UInt32.random(in: 0...UInt32.max)).sock"
        let agent = SSHAgent(socketPath: path)
        let key = SSHAgentKey.generate(comment: "sign-test@phantomkey")
        await agent.addKey(key)
        try await agent.start()
        defer { Task { await agent.stop() } }

        // Connect
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        #expect(fd >= 0)
        defer { close(fd) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        path.utf8CString.withUnsafeBytes { pathBytes in
            withUnsafeMutableBytes(of: &addr.sun_path) { buf in
                let count = min(pathBytes.count, buf.count)
                buf.copyBytes(from: pathBytes.prefix(count))
            }
        }
        _ = withUnsafePointer(to: &addr) { addrPtr in
            addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                connect(fd, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }

        // Build SSH_AGENTC_SIGN_REQUEST
        let dataToSign = Data("test data to sign".utf8)
        var request = Data([13]) // SSH_AGENTC_SIGN_REQUEST
        request.append(SSHWireFormat.encodeString(key.publicKeyBlob))
        request.append(SSHWireFormat.encodeString(dataToSign))
        request.append(SSHWireFormat.encodeUInt32(0)) // flags

        var reqLen = UInt32(request.count).bigEndian
        _ = write(fd, &reqLen, 4)
        _ = request.withUnsafeBytes { write(fd, $0.baseAddress!, $0.count) }

        // Read response
        var respLenBuf = [UInt8](repeating: 0, count: 4)
        #expect(read(fd, &respLenBuf, 4) == 4)
        let respLen = Int(UInt32(respLenBuf[0]) << 24 | UInt32(respLenBuf[1]) << 16
            | UInt32(respLenBuf[2]) << 8 | UInt32(respLenBuf[3]))

        var respBuf = [UInt8](repeating: 0, count: respLen)
        var totalRead = 0
        while totalRead < respLen {
            let n = read(fd, &respBuf[totalRead], respLen - totalRead)
            #expect(n > 0)
            totalRead += n
        }
        let response = Data(respBuf)

        // Response should be SSH_AGENT_SIGN_RESPONSE (14)
        #expect(response[0] == 14)
    }

    @Test("SSHAgentKey generates valid authorized_keys line")
    func authorizedKeyLine() {
        let key = SSHAgentKey.generate(comment: "user@host")
        let line = key.authorizedKeyLine
        #expect(line.hasPrefix("ecdsa-sha2-nistp256 "))
        #expect(line.hasSuffix(" user@host"))
        // The base64 part should be decodable
        let parts = line.split(separator: " ")
        #expect(parts.count == 3)
        #expect(Data(base64Encoded: String(parts[1])) != nil)
    }

    @Test("SSH wire format encodes and decodes strings")
    func wireFormatRoundtrip() {
        let original = Data("hello world".utf8)
        let encoded = SSHWireFormat.encodeString(original)
        var offset = 0
        let decoded = SSHWireFormat.decodeString(encoded, offset: &offset)
        #expect(decoded == original)
        #expect(offset == encoded.count)
    }

    @Test("Multiple keys are listed correctly")
    func multipleKeys() async throws {
        let path = NSTemporaryDirectory() + "pk-\(UInt32.random(in: 0...UInt32.max)).sock"
        let agent = SSHAgent(socketPath: path)
        await agent.addKey(SSHAgentKey.generate(comment: "key1"))
        await agent.addKey(SSHAgentKey.generate(comment: "key2"))
        await agent.addKey(SSHAgentKey.generate(comment: "key3"))
        #expect(await agent.keyCount == 3)
        await agent.removeAllKeys()
        #expect(await agent.keyCount == 0)
    }
}
