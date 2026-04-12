import Foundation

public protocol PolicyPersistence: Sendable {
    func saveRules(_ rules: [PolicyRule]) async throws
    func loadRules() async throws -> [PolicyRule]
    func saveGlobalPolicy(_ policy: GlobalPolicy) async throws
    func loadGlobalPolicy() async throws -> GlobalPolicy?
}

public actor InMemoryPolicyStore: PolicyPersistence {
    private var rules: [PolicyRule] = []
    private var globalPolicy: GlobalPolicy?

    public init() {}

    public func saveRules(_ rules: [PolicyRule]) async throws {
        self.rules = rules
    }

    public func loadRules() async throws -> [PolicyRule] {
        rules
    }

    public func saveGlobalPolicy(_ policy: GlobalPolicy) async throws {
        self.globalPolicy = policy
    }

    public func loadGlobalPolicy() async throws -> GlobalPolicy? {
        globalPolicy
    }
}

public final class JSONFilePolicyStore: PolicyPersistence, @unchecked Sendable {
    private let directoryURL: URL
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init(directory: URL) {
        self.directoryURL = directory
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    }

    public func saveRules(_ rules: [PolicyRule]) async throws {
        let data = try encoder.encode(rules)
        let url = directoryURL.appendingPathComponent("rules.json")
        try data.write(to: url)
    }

    public func loadRules() async throws -> [PolicyRule] {
        let url = directoryURL.appendingPathComponent("rules.json")
        guard FileManager.default.fileExists(atPath: url.path) else {
            return []
        }
        let data = try Data(contentsOf: url)
        return try decoder.decode([PolicyRule].self, from: data)
    }

    public func saveGlobalPolicy(_ policy: GlobalPolicy) async throws {
        let data = try encoder.encode(policy)
        let url = directoryURL.appendingPathComponent("global_policy.json")
        try data.write(to: url)
    }

    public func loadGlobalPolicy() async throws -> GlobalPolicy? {
        let url = directoryURL.appendingPathComponent("global_policy.json")
        guard FileManager.default.fileExists(atPath: url.path) else {
            return nil
        }
        let data = try Data(contentsOf: url)
        return try decoder.decode(GlobalPolicy.self, from: data)
    }
}
