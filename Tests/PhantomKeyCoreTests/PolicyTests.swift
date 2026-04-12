import Testing
import Foundation
@testable import PhantomKeyCore

@Suite("Policy Engine")
struct PolicyTests {
    @Test("Default policy requires user presence")
    func defaultPolicy() async {
        let engine = PolicyEngine()
        let decision = await engine.evaluate(relyingPartyId: "example.com", requiresUV: false)
        #expect(decision == .requireUserPresence)
    }

    @Test("Default policy with UV requires user verification")
    func defaultPolicyUV() async {
        let engine = PolicyEngine()
        let decision = await engine.evaluate(relyingPartyId: "example.com", requiresUV: true)
        #expect(decision == .requireUserVerification)
    }

    @Test("Deny rule blocks signing")
    func denyRule() async {
        let engine = PolicyEngine()
        let rule = PolicyRule.denyRule(for: "evil.com")
        await engine.setRule(rule)

        let decision = await engine.evaluate(relyingPartyId: "evil.com", requiresUV: false)
        #expect(decision == .deny)
    }

    @Test("Auto-approve after manual approval within window")
    func autoApproveWindow() async {
        let engine = PolicyEngine()
        let rule = PolicyRule.autoApproveRule(for: "github.com", durationSeconds: 300)
        await engine.setRule(rule)

        let first = await engine.evaluate(relyingPartyId: "github.com", requiresUV: false)
        #expect(first == .requireUserPresence)

        await engine.recordApproval(relyingPartyId: "github.com")

        let second = await engine.evaluate(relyingPartyId: "github.com", requiresUV: false)
        #expect(second == .approve)
    }

    @Test("Rules are independent per relying party")
    func perRPRules() async {
        let engine = PolicyEngine()
        await engine.setRule(PolicyRule.denyRule(for: "blocked.com"))
        await engine.setRule(PolicyRule.autoApproveRule(for: "trusted.com", durationSeconds: 60))

        let blocked = await engine.evaluate(relyingPartyId: "blocked.com", requiresUV: false)
        #expect(blocked == .deny)

        let trusted = await engine.evaluate(relyingPartyId: "trusted.com", requiresUV: false)
        #expect(trusted == .requireUserPresence)

        let unknown = await engine.evaluate(relyingPartyId: "other.com", requiresUV: false)
        #expect(unknown == .requireUserPresence)
    }

    @Test("Rate limiting denies excess requests")
    func rateLimiting() async {
        let policy = GlobalPolicy(maxSignaturesPerMinute: 3)
        let engine = PolicyEngine(globalPolicy: policy)

        for _ in 0..<3 {
            await engine.recordApproval(relyingPartyId: "example.com")
        }

        let decision = await engine.evaluate(relyingPartyId: "example.com", requiresUV: false)
        #expect(decision == .deny)
    }

    @Test("Remove rule reverts to default behavior")
    func removeRule() async {
        let engine = PolicyEngine()
        await engine.setRule(PolicyRule.denyRule(for: "temp.com"))

        let denied = await engine.evaluate(relyingPartyId: "temp.com", requiresUV: false)
        #expect(denied == .deny)

        await engine.removeRule(relyingPartyId: "temp.com")

        let defaulted = await engine.evaluate(relyingPartyId: "temp.com", requiresUV: false)
        #expect(defaulted == .requireUserPresence)
    }

    @Test("Clear approval cache resets auto-approve")
    func clearCache() async {
        let engine = PolicyEngine()
        let rule = PolicyRule.autoApproveRule(for: "github.com", durationSeconds: 300)
        await engine.setRule(rule)
        await engine.recordApproval(relyingPartyId: "github.com")

        let approved = await engine.evaluate(relyingPartyId: "github.com", requiresUV: false)
        #expect(approved == .approve)

        await engine.clearApprovalCache()

        let reset = await engine.evaluate(relyingPartyId: "github.com", requiresUV: false)
        #expect(reset == .requireUserPresence)
    }

    @Test("Get and set global policy")
    func globalPolicyRoundtrip() async {
        let engine = PolicyEngine()
        let custom = GlobalPolicy(maxSignaturesPerMinute: 5, requireUserPresence: false)
        await engine.setGlobalPolicy(custom)

        let retrieved = await engine.getGlobalPolicy()
        #expect(retrieved.maxSignaturesPerMinute == 5)
        #expect(retrieved.requireUserPresence == false)
    }

    @Test("Get all rules")
    func getAllRules() async {
        let engine = PolicyEngine()
        await engine.setRule(PolicyRule.denyRule(for: "a.com"))
        await engine.setRule(PolicyRule.denyRule(for: "b.com"))

        let rules = await engine.getAllRules()
        #expect(rules.count == 2)
    }
}

@Suite("Policy Rule Model")
struct PolicyRuleTests {
    @Test("Default rule has alwaysAsk action")
    func defaultAction() {
        let rule = PolicyRule.defaultRule(for: "test.com")
        #expect(rule.action == .alwaysAsk)
        #expect(rule.relyingPartyId == "test.com")
    }

    @Test("Auto-approve rule stores duration")
    func autoApproveDuration() {
        let rule = PolicyRule.autoApproveRule(for: "github.com", durationSeconds: 300)
        #expect(rule.action == .autoApprove)
        #expect(rule.autoApproveDurationSeconds == 300)
    }

    @Test("PolicyRule is Codable")
    func codableRoundtrip() throws {
        let rule = PolicyRule.autoApproveRule(for: "github.com", durationSeconds: 300)
        let data = try JSONEncoder().encode(rule)
        let decoded = try JSONDecoder().decode(PolicyRule.self, from: data)
        #expect(decoded.relyingPartyId == rule.relyingPartyId)
        #expect(decoded.action == rule.action)
        #expect(decoded.autoApproveDurationSeconds == rule.autoApproveDurationSeconds)
    }

    @Test("GlobalPolicy is Codable")
    func globalPolicyCodable() throws {
        let policy = GlobalPolicy(maxSignaturesPerMinute: 20, defaultAction: .deny)
        let data = try JSONEncoder().encode(policy)
        let decoded = try JSONDecoder().decode(GlobalPolicy.self, from: data)
        #expect(decoded.maxSignaturesPerMinute == 20)
        #expect(decoded.defaultAction == .deny)
    }
}

@Suite("Concurrent Policy Access")
struct ConcurrentPolicyTests {
    @Test("Concurrent evaluations do not crash")
    func concurrentEvaluations() async {
        let engine = PolicyEngine()
        await engine.setRule(PolicyRule.autoApproveRule(for: "github.com", durationSeconds: 300))
        await engine.recordApproval(relyingPartyId: "github.com")

        await withTaskGroup(of: PolicyDecision.self) { group in
            for i in 0..<50 {
                let rpId = i % 2 == 0 ? "github.com" : "other.com"
                group.addTask {
                    await engine.evaluate(relyingPartyId: rpId, requiresUV: false)
                }
            }
            for await _ in group {}
        }
    }

    @Test("Concurrent rule mutations do not crash")
    func concurrentMutations() async {
        let engine = PolicyEngine()

        await withTaskGroup(of: Void.self) { group in
            for i in 0..<20 {
                group.addTask {
                    await engine.setRule(PolicyRule.denyRule(for: "site\(i).com"))
                }
                group.addTask {
                    await engine.recordApproval(relyingPartyId: "site\(i).com")
                }
            }
        }

        let rules = await engine.getAllRules()
        #expect(rules.count == 20)
    }
}

@Suite("InMemory Policy Store")
struct PolicyStoreTests {
    @Test("Save and load rules")
    func saveLoadRules() async throws {
        let store = InMemoryPolicyStore()
        let rules = [
            PolicyRule.denyRule(for: "a.com"),
            PolicyRule.autoApproveRule(for: "b.com", durationSeconds: 60),
        ]

        try await store.saveRules(rules)
        let loaded = try await store.loadRules()
        #expect(loaded.count == 2)
    }

    @Test("Save and load global policy")
    func saveLoadGlobalPolicy() async throws {
        let store = InMemoryPolicyStore()
        let policy = GlobalPolicy(maxSignaturesPerMinute: 5)

        try await store.saveGlobalPolicy(policy)
        let loaded = try await store.loadGlobalPolicy()
        #expect(loaded?.maxSignaturesPerMinute == 5)
    }

    @Test("Load from empty store returns empty/nil")
    func emptyStore() async throws {
        let store = InMemoryPolicyStore()
        let rules = try await store.loadRules()
        #expect(rules.isEmpty)
        let policy = try await store.loadGlobalPolicy()
        #expect(policy == nil)
    }
}
