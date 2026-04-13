#if canImport(SystemExtensions)
import Foundation
import SystemExtensions
import os.log

/// Activates the PhantomKey DriverKit system extension on first launch.
/// The user must approve it in System Settings > General > Login Items & Extensions > Driver Extensions.
class SystemExtensionActivator: NSObject, OSSystemExtensionRequestDelegate {
    static let driverExtensionIdentifier = "md.thomas.phantomkey.mac.driver"
    private let logger = Logger(subsystem: "md.thomas.phantomkey.mac", category: "SystemExtension")
    private var onCompletion: ((Bool) -> Void)?

    /// Request activation of the driver extension.
    /// On first run, macOS shows a dialog directing the user to System Settings to approve.
    func activate(completion: ((Bool) -> Void)? = nil) {
        onCompletion = completion
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: Self.driverExtensionIdentifier,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
        logger.info("Submitted system extension activation request")
    }

    // MARK: - OSSystemExtensionRequestDelegate

    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        logger.info("Replacing existing extension \(existing.bundleShortVersion) with \(ext.bundleShortVersion)")
        return .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        logger.info("System extension needs user approval in System Settings")
    }

    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        switch result {
        case .completed:
            logger.info("System extension activated successfully")
            onCompletion?(true)
        case .willCompleteAfterReboot:
            logger.info("System extension will complete after reboot")
            onCompletion?(true)
        @unknown default:
            logger.warning("System extension returned unknown result: \(result.rawValue)")
            onCompletion?(false)
        }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        logger.error("System extension activation failed: \(error.localizedDescription)")
        onCompletion?(false)
    }
}
#endif
