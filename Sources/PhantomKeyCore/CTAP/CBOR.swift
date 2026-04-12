import Foundation

public enum CBORValue: Equatable, Sendable {
    case unsignedInt(UInt64)
    case negativeInt(Int64)
    case byteString(Data)
    case textString(String)
    case array([CBORValue])
    case map([(CBORValue, CBORValue)])
    case bool(Bool)
    case null
    case simple(UInt8)
    indirect case tagged(UInt64, CBORValue)

    public static func == (lhs: CBORValue, rhs: CBORValue) -> Bool {
        switch (lhs, rhs) {
        case (.unsignedInt(let a), .unsignedInt(let b)): return a == b
        case (.negativeInt(let a), .negativeInt(let b)): return a == b
        case (.byteString(let a), .byteString(let b)): return a == b
        case (.textString(let a), .textString(let b)): return a == b
        case (.array(let a), .array(let b)): return a == b
        case (.bool(let a), .bool(let b)): return a == b
        case (.null, .null): return true
        case (.simple(let a), .simple(let b)): return a == b
        case (.tagged(let tagA, let valA), .tagged(let tagB, let valB)):
            return tagA == tagB && valA == valB
        case (.map(let a), .map(let b)):
            guard a.count == b.count else { return false }
            for (i, pair) in a.enumerated() {
                if pair.0 != b[i].0 || pair.1 != b[i].1 { return false }
            }
            return true
        default: return false
        }
    }
}

public enum CBORError: Error, Sendable {
    case unexpectedEnd
    case invalidFormat
    case unsupportedType(UInt8)
    case invalidUTF8
    case nestingTooDeep
    case containerTooLarge
}

public struct CBOREncoder: Sendable {
    public init() {}

    public func encode(_ value: CBORValue) -> Data {
        var data = Data()
        encodeValue(value, into: &data)
        return data
    }

    private func encodeValue(_ value: CBORValue, into data: inout Data) {
        switch value {
        case .unsignedInt(let n):
            encodeUnsigned(majorType: 0, value: n, into: &data)
        case .negativeInt(let n):
            encodeUnsigned(majorType: 1, value: UInt64(-(n + 1)), into: &data)
        case .byteString(let bytes):
            encodeUnsigned(majorType: 2, value: UInt64(bytes.count), into: &data)
            data.append(bytes)
        case .textString(let str):
            let utf8 = Data(str.utf8)
            encodeUnsigned(majorType: 3, value: UInt64(utf8.count), into: &data)
            data.append(utf8)
        case .array(let items):
            encodeUnsigned(majorType: 4, value: UInt64(items.count), into: &data)
            for item in items {
                encodeValue(item, into: &data)
            }
        case .map(let pairs):
            encodeUnsigned(majorType: 5, value: UInt64(pairs.count), into: &data)
            for (key, val) in pairs {
                encodeValue(key, into: &data)
                encodeValue(val, into: &data)
            }
        case .tagged(let tag, let inner):
            encodeUnsigned(majorType: 6, value: tag, into: &data)
            encodeValue(inner, into: &data)
        case .bool(let b):
            data.append(b ? 0xF5 : 0xF4)
        case .null:
            data.append(0xF6)
        case .simple(let s):
            if s < 24 {
                data.append(0xE0 | s)
            } else {
                data.append(0xF8)
                data.append(s)
            }
        }
    }

    private func encodeUnsigned(majorType: UInt8, value: UInt64, into data: inout Data) {
        let mt = majorType << 5
        if value < 24 {
            data.append(mt | UInt8(value))
        } else if value <= UInt8.max {
            data.append(mt | 24)
            data.append(UInt8(value))
        } else if value <= UInt16.max {
            data.append(mt | 25)
            var be = UInt16(value).bigEndian
            data.append(Data(bytes: &be, count: 2))
        } else if value <= UInt32.max {
            data.append(mt | 26)
            var be = UInt32(value).bigEndian
            data.append(Data(bytes: &be, count: 4))
        } else {
            data.append(mt | 27)
            var be = value.bigEndian
            data.append(Data(bytes: &be, count: 8))
        }
    }
}

public struct CBORDecoder: Sendable {
    public static let maxNestingDepth = 32
    public static let maxContainerSize = 65536

    public init() {}

    public func decode(_ data: Data) throws -> CBORValue {
        var offset = 0
        return try decodeValue(data, offset: &offset, depth: 0)
    }

    private func decodeValue(_ data: Data, offset: inout Int, depth: Int) throws -> CBORValue {
        guard depth < Self.maxNestingDepth else { throw CBORError.nestingTooDeep }
        guard offset < data.count else { throw CBORError.unexpectedEnd }

        let initial = data[offset]
        offset += 1
        let majorType = initial >> 5
        let additionalInfo = initial & 0x1F

        switch majorType {
        case 0:
            let n = try decodeUnsigned(additionalInfo, data: data, offset: &offset)
            return .unsignedInt(n)
        case 1:
            let n = try decodeUnsigned(additionalInfo, data: data, offset: &offset)
            return .negativeInt(-1 - Int64(n))
        case 2:
            let len = try decodeUnsigned(additionalInfo, data: data, offset: &offset)
            let count = Int(len)
            guard count <= Self.maxContainerSize else { throw CBORError.containerTooLarge }
            guard offset + count <= data.count else { throw CBORError.unexpectedEnd }
            let bytes = data[offset..<(offset + count)]
            offset += count
            return .byteString(Data(bytes))
        case 3:
            let len = try decodeUnsigned(additionalInfo, data: data, offset: &offset)
            let count = Int(len)
            guard count <= Self.maxContainerSize else { throw CBORError.containerTooLarge }
            guard offset + count <= data.count else { throw CBORError.unexpectedEnd }
            let bytes = data[offset..<(offset + count)]
            offset += count
            guard let str = String(data: Data(bytes), encoding: .utf8) else {
                throw CBORError.invalidUTF8
            }
            return .textString(str)
        case 4:
            let count = try decodeUnsigned(additionalInfo, data: data, offset: &offset)
            guard count <= Self.maxContainerSize else { throw CBORError.containerTooLarge }
            var items: [CBORValue] = []
            items.reserveCapacity(Int(min(count, 256)))
            for _ in 0..<count {
                items.append(try decodeValue(data, offset: &offset, depth: depth + 1))
            }
            return .array(items)
        case 5:
            let count = try decodeUnsigned(additionalInfo, data: data, offset: &offset)
            guard count <= Self.maxContainerSize else { throw CBORError.containerTooLarge }
            var pairs: [(CBORValue, CBORValue)] = []
            pairs.reserveCapacity(Int(min(count, 256)))
            for _ in 0..<count {
                let key = try decodeValue(data, offset: &offset, depth: depth + 1)
                let val = try decodeValue(data, offset: &offset, depth: depth + 1)
                pairs.append((key, val))
            }
            return .map(pairs)
        case 6:
            let tag = try decodeUnsigned(additionalInfo, data: data, offset: &offset)
            let inner = try decodeValue(data, offset: &offset, depth: depth + 1)
            return .tagged(tag, inner)
        case 7:
            switch additionalInfo {
            case 20: return .bool(false)
            case 21: return .bool(true)
            case 22: return .null
            case 24:
                guard offset < data.count else { throw CBORError.unexpectedEnd }
                let s = data[offset]
                offset += 1
                return .simple(s)
            default:
                if additionalInfo < 24 {
                    return .simple(additionalInfo)
                }
                throw CBORError.unsupportedType(initial)
            }
        default:
            throw CBORError.unsupportedType(initial)
        }
    }

    private func decodeUnsigned(_ info: UInt8, data: Data, offset: inout Int) throws -> UInt64 {
        if info < 24 {
            return UInt64(info)
        } else if info == 24 {
            guard offset < data.count else { throw CBORError.unexpectedEnd }
            let val = data[offset]
            offset += 1
            return UInt64(val)
        } else if info == 25 {
            guard offset + 2 <= data.count else { throw CBORError.unexpectedEnd }
            let val = UInt16(data[offset]) << 8 | UInt16(data[offset + 1])
            offset += 2
            return UInt64(val)
        } else if info == 26 {
            guard offset + 4 <= data.count else { throw CBORError.unexpectedEnd }
            let val = UInt32(data[offset]) << 24 | UInt32(data[offset + 1]) << 16
                | UInt32(data[offset + 2]) << 8 | UInt32(data[offset + 3])
            offset += 4
            return UInt64(val)
        } else if info == 27 {
            guard offset + 8 <= data.count else { throw CBORError.unexpectedEnd }
            var val: UInt64 = 0
            for i in 0..<8 {
                val = val << 8 | UInt64(data[offset + i])
            }
            offset += 8
            return val
        }
        throw CBORError.invalidFormat
    }
}
