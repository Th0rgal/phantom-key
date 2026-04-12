import Foundation

public enum PolicyAction: String, Sendable, Codable {
    case alwaysAsk
    case autoApprove
    case deny
    case timeWindow
}

public struct PolicyRule: Sendable, Codable, Identifiable {
    public let id: String
    public let relyingPartyId: String
    public let action: PolicyAction
    public let autoApproveDurationSeconds: Int?
    public let timeWindowStart: String?
    public let timeWindowEnd: String?
    public let createdAt: Date
    public let updatedAt: Date

    public init(
        id: String = UUID().uuidString,
        relyingPartyId: String,
        action: PolicyAction,
        autoApproveDurationSeconds: Int? = nil,
        timeWindowStart: String? = nil,
        timeWindowEnd: String? = nil
    ) {
        self.id = id
        self.relyingPartyId = relyingPartyId
        self.action = action
        self.autoApproveDurationSeconds = autoApproveDurationSeconds
        self.timeWindowStart = timeWindowStart
        self.timeWindowEnd = timeWindowEnd
        self.createdAt = Date()
        self.updatedAt = Date()
    }

    public static func defaultRule(for rpId: String) -> PolicyRule {
        PolicyRule(relyingPartyId: rpId, action: .alwaysAsk)
    }

    public static func autoApproveRule(for rpId: String, durationSeconds: Int) -> PolicyRule {
        PolicyRule(
            relyingPartyId: rpId,
            action: .autoApprove,
            autoApproveDurationSeconds: durationSeconds
        )
    }

    public static func denyRule(for rpId: String) -> PolicyRule {
        PolicyRule(relyingPartyId: rpId, action: .deny)
    }
}

public struct GlobalPolicy: Sendable, Codable {
    public var maxSignaturesPerMinute: Int
    public var requireUserPresence: Bool
    public var requireUserVerification: Bool
    public var defaultAction: PolicyAction
    public var autoLockTimeoutSeconds: Int

    public init(
        maxSignaturesPerMinute: Int = 10,
        requireUserPresence: Bool = true,
        requireUserVerification: Bool = true,
        defaultAction: PolicyAction = .alwaysAsk,
        autoLockTimeoutSeconds: Int = 300
    ) {
        self.maxSignaturesPerMinute = maxSignaturesPerMinute
        self.requireUserPresence = requireUserPresence
        self.requireUserVerification = requireUserVerification
        self.defaultAction = defaultAction
        self.autoLockTimeoutSeconds = autoLockTimeoutSeconds
    }
}
