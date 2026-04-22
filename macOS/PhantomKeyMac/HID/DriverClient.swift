#if canImport(IOKit)
import Foundation
import IOKit
import os.log

/// Communicates with the PhantomKey DriverKit HID device via IOKit user client.
///
/// Two directions:
/// - `sendReport(_:)`: host app → driver → HID stack (input reports browsers read)
/// - `onReceiveReport`: HID stack → driver → host app (output reports browsers write)
///
/// The driver's user client has a single external method family (SendReport,
/// RegisterReportCallback). Registration opens an async completion channel so
/// the driver can push setReport bytes up without polling.
final class DriverClient {
    static let serviceName = "PhantomKeyHIDDevice"

    // Must match the enum in PhantomKeyHIDUserClient.iig
    private static let kMethodSendReport: UInt32 = 0
    private static let kMethodRegisterReportCallback: UInt32 = 1

    private var connection: io_connect_t = 0
    private var isConnected = false
    private var notificationPort: IONotificationPortRef?

    private let logger = Logger(subsystem: "md.thomas.phantomkey.mac", category: "DriverClient")

    /// Invoked on the main runloop when the driver forwards an output report
    /// (browser-written CTAP HID packet). Always 64 bytes.
    var onReceiveReport: ((Data) -> Void)?

    /// Connect to the driver's user client and register for async setReport
    /// notifications.
    func connect() throws {
        guard !isConnected else { return }

        let matching = IOServiceNameMatching(Self.serviceName)
        let service = IOServiceGetMatchingService(kIOMainPortDefault, matching)
        guard service != IO_OBJECT_NULL else {
            throw DriverClientError.serviceNotFound
        }
        defer { IOObjectRelease(service) }

        let openResult = IOServiceOpen(service, mach_task_self_, 0, &connection)
        guard openResult == kIOReturnSuccess else {
            throw DriverClientError.openFailed(openResult)
        }
        isConnected = true

        try registerAsyncCallback()
    }

    /// Send a 64-byte HID report to the driver, which delivers it to the HID
    /// stack so browsers/libfido2 can read it as an input report.
    func sendReport(_ report: Data) throws {
        guard isConnected else { throw DriverClientError.notConnected }
        guard report.count == 64 else { throw DriverClientError.invalidReportSize }

        let result = report.withUnsafeBytes { buf in
            IOConnectCallStructMethod(
                connection,
                Self.kMethodSendReport,
                buf.baseAddress!,
                report.count,
                nil,
                nil
            )
        }

        guard result == kIOReturnSuccess else {
            throw DriverClientError.sendFailed(result)
        }
    }

    /// Disconnect from the driver and tear down the notification port.
    func disconnect() {
        if let port = notificationPort {
            IONotificationPortDestroy(port)
            notificationPort = nil
        }
        if isConnected {
            IOServiceClose(connection)
            connection = 0
            isConnected = false
        }
    }

    deinit {
        disconnect()
    }

    // MARK: - Async callback plumbing

    private func registerAsyncCallback() throws {
        let port = IONotificationPortCreate(kIOMainPortDefault)
        guard let port else { throw DriverClientError.notificationPortFailed }
        notificationPort = port

        let machPort = IONotificationPortGetMachPort(port)
        if let source = IONotificationPortGetRunLoopSource(port)?.takeUnretainedValue() {
            CFRunLoopAddSource(CFRunLoopGetMain(), source, .defaultMode)
        }

        // IOKit async reference layout: [0] = callback fn, [1] = refcon,
        // remaining slots are scratch space for IOKit.
        var asyncRef = [UInt64](repeating: 0, count: 8)
        let fnPtr = unsafeBitCast(Self.asyncCallback, to: UnsafeRawPointer.self)
        asyncRef[0] = UInt64(UInt(bitPattern: fnPtr))
        asyncRef[1] = UInt64(UInt(bitPattern: Unmanaged.passUnretained(self).toOpaque()))

        let result = asyncRef.withUnsafeMutableBufferPointer { ref -> kern_return_t in
            IOConnectCallAsyncScalarMethod(
                connection,
                Self.kMethodRegisterReportCallback,
                machPort,
                ref.baseAddress,
                UInt32(ref.count),
                nil, 0,
                nil, nil
            )
        }

        guard result == kIOReturnSuccess else {
            throw DriverClientError.registerCallbackFailed(result)
        }
        logger.info("Registered async setReport callback")
    }

    /// C callback IOKit invokes on the runloop thread when the driver calls
    /// AsyncCompletion. `args` holds 8 pointer-sized slots (one per u64 packed
    /// by the driver); we splice them back into a 64-byte report.
    private static let asyncCallback: IOAsyncCallback = { refcon, result, args, numArgs in
        guard let refcon else { return }
        let client = Unmanaged<DriverClient>.fromOpaque(refcon).takeUnretainedValue()
        guard result == kIOReturnSuccess, let args, numArgs >= 8 else { return }

        var report = Data(count: 64)
        report.withUnsafeMutableBytes { buf in
            let u64Buf = buf.baseAddress!.assumingMemoryBound(to: UInt64.self)
            for i in 0..<8 {
                u64Buf[i] = UInt64(UInt(bitPattern: args[Int(i)]))
            }
        }
        client.onReceiveReport?(report)
    }
}

enum DriverClientError: Error {
    case serviceNotFound
    case openFailed(kern_return_t)
    case notConnected
    case invalidReportSize
    case sendFailed(kern_return_t)
    case notificationPortFailed
    case registerCallbackFailed(kern_return_t)
}
#endif
