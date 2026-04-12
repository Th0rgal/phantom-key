import Foundation
import Crypto

/// CTAP 2.1 Large Blob Storage.
/// Stores an array of opaque blobs associated with credentials via largeBlobKey.
/// The blob array is CBOR-encoded followed by a truncated SHA-256 hash for integrity.
public actor LargeBlobStorage {
    public static let hashLength = 16
    private var blobArray: Data
    private let maxSize: Int

    public init(maxSize: Int = 4096) {
        self.maxSize = maxSize
        // Initialize with empty array: CBOR empty array (0x80) + 16-byte SHA-256 hash
        let emptyArray = CBOREncoder().encode(.array([]))
        var initial = emptyArray
        let hash = Data(SHA256.hash(data: emptyArray)).prefix(Self.hashLength)
        initial.append(hash)
        self.blobArray = initial
    }

    public var serializedSize: Int { blobArray.count }

    public func read(offset: Int, count: Int) -> Data {
        let start = min(offset, blobArray.count)
        let end = min(start + count, blobArray.count)
        return Data(blobArray[start..<end])
    }

    public func write(data: Data, offset: Int, length: Int) throws {
        guard offset + data.count <= maxSize else {
            throw LargeBlobError.storageFull
        }

        if offset == 0 {
            // Start of new write — replace from beginning
            blobArray = data
        } else {
            // Continuation write — append
            guard offset == blobArray.count else {
                throw LargeBlobError.invalidOffset
            }
            blobArray.append(data)
        }

        // If this is the final fragment (we've received `length` bytes total), verify integrity
        if blobArray.count == length {
            try verifyIntegrity()
        }
    }

    public func verifyIntegrity() throws {
        guard blobArray.count > Self.hashLength else {
            throw LargeBlobError.integrityFailure
        }
        let content = blobArray.prefix(blobArray.count - Self.hashLength)
        let storedHash = blobArray.suffix(Self.hashLength)
        let computedHash = Data(SHA256.hash(data: content)).prefix(Self.hashLength)
        guard storedHash == computedHash else {
            throw LargeBlobError.integrityFailure
        }
    }

    /// Get the raw entries from the blob array (excluding the trailing hash).
    public func entries() throws -> [LargeBlobEntry] {
        guard blobArray.count > Self.hashLength else { return [] }
        let content = Data(blobArray.prefix(blobArray.count - Self.hashLength))
        let decoded = try CBORDecoder().decode(content)
        guard case .array(let items) = decoded else { return [] }

        return items.compactMap { item -> LargeBlobEntry? in
            guard case .map(let pairs) = item else { return nil }
            var ciphertext: Data?
            var nonce: Data?
            var origSize: Int?
            for (key, value) in pairs {
                switch key {
                case .unsignedInt(1): if case .byteString(let d) = value { ciphertext = d }
                case .unsignedInt(2): if case .byteString(let d) = value { nonce = d }
                case .unsignedInt(3): if case .unsignedInt(let n) = value { origSize = Int(n) }
                default: break
                }
            }
            guard let ct = ciphertext, let n = nonce else { return nil }
            return LargeBlobEntry(ciphertext: ct, nonce: n, origSize: origSize ?? ct.count)
        }
    }

    /// Replace the entire blob array with new entries.
    public func setEntries(_ entries: [LargeBlobEntry]) throws {
        let items: [CBORValue] = entries.map { entry in
            .map([
                (.unsignedInt(1), .byteString(entry.ciphertext)),
                (.unsignedInt(2), .byteString(entry.nonce)),
                (.unsignedInt(3), .unsignedInt(UInt64(entry.origSize))),
            ])
        }
        let encoded = CBOREncoder().encode(.array(items))
        let hash = Data(SHA256.hash(data: encoded)).prefix(Self.hashLength)
        var newArray = encoded
        newArray.append(hash)
        guard newArray.count <= maxSize else {
            throw LargeBlobError.storageFull
        }
        blobArray = newArray
    }
}

public struct LargeBlobEntry: Sendable {
    public let ciphertext: Data
    public let nonce: Data
    public let origSize: Int

    public init(ciphertext: Data, nonce: Data, origSize: Int) {
        self.ciphertext = ciphertext
        self.nonce = nonce
        self.origSize = origSize
    }
}

public enum LargeBlobError: Error, Sendable {
    case storageFull
    case invalidOffset
    case integrityFailure
}
