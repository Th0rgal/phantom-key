import Foundation

public enum PolicyDecision: Sendable {
    case approve
    case deny
    case requireUserPresence
    case requireUserVerification
}

public actor PolicyEngine {
    private var rules: [String: PolicyRule] = [:]
    private var globalPolicy: GlobalPolicy
    private var approvalTimestamps: [String: Date] = [:]
    private var signatureLog: [Date] = []

    public init(globalPolicy: GlobalPolicy = GlobalPolicy()) {
        self.globalPolicy = globalPolicy
    }

    public func evaluate(relyingPartyId: String, requiresUV: Bool) -> PolicyDecision {
        pruneSignatureLog()

        if signatureLog.count >= globalPolicy.maxSignaturesPerMinute {
            return .deny
        }

        let rule = rules[relyingPartyId] ?? PolicyRule.defaultRule(for: relyingPartyId)

        switch rule.action {
        case .deny:
            return .deny
        case .alwaysAsk:
            return requiresUV ? .requireUserVerification : .requireUserPresence
        case .autoApprove:
            if let lastApproval = approvalTimestamps[relyingPartyId],
               let duration = rule.autoApproveDurationSeconds {
                let elapsed = Date().timeIntervalSince(lastApproval)
                if elapsed < Double(duration) {
                    return .approve
                }
            }
            return requiresUV ? .requireUserVerification : .requireUserPresence
        case .timeWindow:
            if isWithinTimeWindow(rule: rule) {
                return .approve
            }
            return .deny
        }
    }

    public func recordApproval(relyingPartyId: String) {
        approvalTimestamps[relyingPartyId] = Date()
        signatureLog.append(Date())
    }

    public func setRule(_ rule: PolicyRule) {
        rules[rule.relyingPartyId] = rule
    }

    public func removeRule(relyingPartyId: String) {
        rules.removeValue(forKey: relyingPartyId)
    }

    public func getRule(relyingPartyId: String) -> PolicyRule? {
        rules[relyingPartyId]
    }

    public func getAllRules() -> [PolicyRule] {
        Array(rules.values)
    }

    public func setGlobalPolicy(_ policy: GlobalPolicy) {
        self.globalPolicy = policy
    }

    public func getGlobalPolicy() -> GlobalPolicy {
        globalPolicy
    }

    public func clearApprovalCache() {
        approvalTimestamps.removeAll()
    }

    private func pruneSignatureLog() {
        let cutoff = Date().addingTimeInterval(-60)
        signatureLog.removeAll { $0 < cutoff }
    }

    private func isWithinTimeWindow(rule: PolicyRule) -> Bool {
        guard let startStr = rule.timeWindowStart,
              let endStr = rule.timeWindowEnd else {
            return false
        }

        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm"

        let now = formatter.string(from: Date())
        return now >= startStr && now <= endStr
    }
}
