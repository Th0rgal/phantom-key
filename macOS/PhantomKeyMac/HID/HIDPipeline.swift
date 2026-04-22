#if canImport(IOKit)
import Foundation
import IOKit
import os.log
import PhantomKeyCore

/// Glues the DriverKit `DriverClient` to the CTAPHID reassembler
/// (`VirtualHIDController`) and forwards CTAP requests to the iPhone via
/// `BridgeController`.
///
/// Flow per output report from the HID stack:
///   driver `setReport` → `DriverClient.onReceiveReport` → this pipeline
///   → `VirtualHIDController.handleHIDReport` (awaits BLE round-trip)
///   → `DriverClient.sendReport` for each response frame
///
/// Reports are pumped through a single-consumer `AsyncStream` so reassembly
/// state in `VirtualHIDController` (`pendingData`, sequence counters) is
/// accessed serially even though `handleHIDReport` suspends on the BLE call.
final class HIDPipeline {
    private let logger = Logger(subsystem: "md.thomas.phantomkey.mac", category: "HIDPipeline")
    private let client = DriverClient()
    private let controller: VirtualHIDController
    private var consumerTask: Task<Void, Never>?

    init(bridge: BridgeController) {
        controller = VirtualHIDController(bridge: bridge)
    }

    /// Try to attach to the driver, retrying while the system extension
    /// finishes activating (first-run user approval can take a while).
    func start() {
        var reportStreamContinuation: AsyncStream<Data>.Continuation!
        let reports = AsyncStream<Data> { reportStreamContinuation = $0 }
        let continuation = reportStreamContinuation!
        client.onReceiveReport = { report in
            continuation.yield(report)
        }

        consumerTask = Task { [controller, client, logger] in
            for await report in reports {
                do {
                    let responses = try await controller.handleHIDReport(report)
                    for response in responses {
                        try client.sendReport(response)
                    }
                } catch {
                    logger.error("HID processing failed: \(String(describing: error), privacy: .public)")
                }
            }
        }

        Task { [weak self] in
            await self?.connectWithRetry()
        }
    }

    func stop() {
        consumerTask?.cancel()
        consumerTask = nil
        client.disconnect()
    }

    private func connectWithRetry() async {
        // Extension activation on first run can take seconds. Retry up to
        // ~30s with a 1s cadence; after that, give up and let the user
        // relaunch once they've approved the extension.
        for attempt in 1...30 {
            do {
                try client.connect()
                logger.info("Connected to PhantomKey driver on attempt \(attempt)")
                return
            } catch {
                if attempt == 30 {
                    logger.error("Giving up on driver connect after \(attempt) attempts: \(String(describing: error), privacy: .public)")
                    return
                }
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
        }
    }
}
#endif
