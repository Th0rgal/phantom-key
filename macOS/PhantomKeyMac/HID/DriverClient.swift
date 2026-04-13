#if canImport(IOKit)
import Foundation
import IOKit

/// Communicates with the PhantomKey DriverKit HID device via IOKit user client.
/// Sends 64-byte HID reports to the driver, which posts them to the HID stack
/// where browsers and libfido2 read them.
class DriverClient {
    private var connection: io_connect_t = 0
    private var isConnected = false

    static let serviceName = "PhantomKeyHIDDevice"

    /// Connect to the driver's user client.
    func connect() throws {
        guard !isConnected else { return }

        let matching = IOServiceNameMatching(Self.serviceName)
        let service = IOServiceGetMatchingService(kIOMainPortDefault, matching)
        guard service != IO_OBJECT_NULL else {
            throw DriverClientError.serviceNotFound
        }
        defer { IOObjectRelease(service) }

        let result = IOServiceOpen(service, mach_task_self_, 0, &connection)
        guard result == kIOReturnSuccess else {
            throw DriverClientError.openFailed(result)
        }

        isConnected = true
    }

    /// Send a 64-byte HID report to the driver, which delivers it to the HID stack.
    /// This is how the host app sends CTAP responses back to browsers/libfido2.
    func sendReport(_ report: Data) throws {
        guard isConnected else { throw DriverClientError.notConnected }
        guard report.count == 64 else { throw DriverClientError.invalidReportSize }

        let result = report.withUnsafeBytes { buf in
            IOConnectCallStructMethod(
                connection,
                0, // kPhantomKeyMethodSendReport
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

    /// Disconnect from the driver.
    func disconnect() {
        if isConnected {
            IOServiceClose(connection)
            connection = 0
            isConnected = false
        }
    }

    deinit {
        disconnect()
    }
}

enum DriverClientError: Error {
    case serviceNotFound
    case openFailed(kern_return_t)
    case notConnected
    case invalidReportSize
    case sendFailed(kern_return_t)
}
#endif
