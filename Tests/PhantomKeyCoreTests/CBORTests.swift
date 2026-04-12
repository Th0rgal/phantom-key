import Testing
import Foundation
@testable import PhantomKeyCore

@Suite("CBOR Encoding/Decoding")
struct CBORTests {
    let encoder = CBOREncoder()
    let decoder = CBORDecoder()

    @Test("Encode and decode unsigned integers")
    func unsignedIntegers() throws {
        let cases: [UInt64] = [0, 1, 23, 24, 255, 256, 65535, 65536, 4294967295, 4294967296]
        for n in cases {
            let encoded = encoder.encode(.unsignedInt(n))
            let decoded = try decoder.decode(encoded)
            #expect(decoded == .unsignedInt(n), "Failed for \(n)")
        }
    }

    @Test("Encode and decode negative integers")
    func negativeIntegers() throws {
        let cases: [Int64] = [-1, -24, -25, -256, -257]
        for n in cases {
            let encoded = encoder.encode(.negativeInt(n))
            let decoded = try decoder.decode(encoded)
            #expect(decoded == .negativeInt(n), "Failed for \(n)")
        }
    }

    @Test("Encode and decode byte strings")
    func byteStrings() throws {
        let testData = Data([0x01, 0x02, 0x03, 0x04])
        let encoded = encoder.encode(.byteString(testData))
        let decoded = try decoder.decode(encoded)
        #expect(decoded == .byteString(testData))
    }

    @Test("Encode and decode empty byte string")
    func emptyByteString() throws {
        let encoded = encoder.encode(.byteString(Data()))
        let decoded = try decoder.decode(encoded)
        #expect(decoded == .byteString(Data()))
    }

    @Test("Encode and decode text strings")
    func textStrings() throws {
        let cases = ["", "hello", "FIDO_2_0", "example.com"]
        for str in cases {
            let encoded = encoder.encode(.textString(str))
            let decoded = try decoder.decode(encoded)
            #expect(decoded == .textString(str), "Failed for '\(str)'")
        }
    }

    @Test("Encode and decode arrays")
    func arrays() throws {
        let arr: CBORValue = .array([
            .unsignedInt(1),
            .textString("two"),
            .bool(true),
        ])
        let encoded = encoder.encode(arr)
        let decoded = try decoder.decode(encoded)
        #expect(decoded == arr)
    }

    @Test("Encode and decode nested arrays")
    func nestedArrays() throws {
        let arr: CBORValue = .array([
            .array([.unsignedInt(1), .unsignedInt(2)]),
            .array([.unsignedInt(3), .unsignedInt(4)]),
        ])
        let encoded = encoder.encode(arr)
        let decoded = try decoder.decode(encoded)
        #expect(decoded == arr)
    }

    @Test("Encode and decode maps")
    func maps() throws {
        let map: CBORValue = .map([
            (.textString("key1"), .unsignedInt(42)),
            (.textString("key2"), .bool(false)),
        ])
        let encoded = encoder.encode(map)
        let decoded = try decoder.decode(encoded)
        #expect(decoded == map)
    }

    @Test("Encode and decode booleans")
    func booleans() throws {
        for b in [true, false] {
            let encoded = encoder.encode(.bool(b))
            let decoded = try decoder.decode(encoded)
            #expect(decoded == .bool(b))
        }
    }

    @Test("Encode and decode null")
    func nullValue() throws {
        let encoded = encoder.encode(.null)
        let decoded = try decoder.decode(encoded)
        #expect(decoded == .null)
    }

    @Test("Decode truncated data throws error")
    func truncatedData() {
        let data = Data([0x44, 0x01, 0x02]) // byte string says 4 bytes, only 2 present
        #expect(throws: CBORError.self) {
            try decoder.decode(data)
        }
    }

    @Test("Decode empty data throws error")
    func emptyData() {
        #expect(throws: CBORError.self) {
            try decoder.decode(Data())
        }
    }

    @Test("CTAP2 authenticatorGetInfo response roundtrip")
    func authenticatorGetInfoCBOR() throws {
        let info = AuthenticatorInfo.phantomKey.toCBOR()
        let encoded = encoder.encode(info)
        let decoded = try decoder.decode(encoded)

        if case .map(let pairs) = decoded {
            #expect(pairs.count >= 5)

            let firstKey = pairs[0].0
            #expect(firstKey == .unsignedInt(0x01))

            if case .array(let versions) = pairs[0].1 {
                #expect(versions.contains(.textString("FIDO_2_0")))
            }
        } else {
            Issue.record("Expected map")
        }
    }
}
