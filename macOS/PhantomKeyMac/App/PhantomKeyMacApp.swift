#if canImport(AppKit)
import SwiftUI
import PhantomKeyCore
import CoreImage.CIFilterBuiltins

// Pure AppDelegate-based lifecycle — the correct pattern for menu bar (LSUIElement) apps.
// SwiftUI's App protocol and its WindowGroup/Settings scenes don't work reliably
// when the app has no main window and runs as an accessory.

@main
class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem?
    private var bridgeController: BridgeController?
    private var pairingWindow: NSWindow?
    private var settingsWindow: NSWindow?
    #if canImport(SystemExtensions)
    private var extensionActivator: SystemExtensionActivator?
    #endif

    static func main() {
        let app = NSApplication.shared
        let delegate = AppDelegate()
        app.delegate = delegate
        app.run()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        setupMenuBar()
        bridgeController = BridgeController()
        bridgeController?.start()

        // Activate the DriverKit system extension
        #if canImport(SystemExtensions)
        extensionActivator = SystemExtensionActivator()
        extensionActivator?.activate()
        #endif
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    // MARK: - Menu Bar

    private func setupMenuBar() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.squareLength)

        if let button = statusItem?.button {
            button.image = NSImage(systemSymbolName: "key.fill", accessibilityDescription: "PhantomKey")
        }

        let menu = NSMenu()
        menu.addItem(NSMenuItem(title: "Status: Searching for iPhone...", action: nil, keyEquivalent: ""))
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "Pair New Device...", action: #selector(showPairing), keyEquivalent: "p"))
        menu.addItem(NSMenuItem(title: "Recent Activity", action: #selector(showActivity), keyEquivalent: "a"))
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "Settings...", action: #selector(showSettings), keyEquivalent: ","))
        menu.addItem(NSMenuItem.separator())
        menu.addItem(NSMenuItem(title: "Quit PhantomKey", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))

        statusItem?.menu = menu
    }

    // MARK: - Windows

    private func showOrCreateWindow(
        _ stored: inout NSWindow?,
        title: String,
        size: NSSize,
        content: some View
    ) {
        if let existing = stored, existing.isVisible {
            existing.makeKeyAndOrderFront(nil)
            NSApp.activate(ignoringOtherApps: true)
            return
        }
        let window = NSWindow(
            contentRect: NSRect(origin: .zero, size: size),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        window.title = title
        window.contentView = NSHostingView(rootView: content)
        window.center()
        window.isReleasedWhenClosed = false
        stored = window
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
    }

    @objc private func showPairing() {
        showOrCreateWindow(&pairingWindow, title: "Pair iPhone", size: NSSize(width: 400, height: 500), content: PairingView())
    }

    @objc private func showActivity() {}

    @objc private func showSettings() {
        showOrCreateWindow(&settingsWindow, title: "PhantomKey Settings", size: NSSize(width: 450, height: 320), content: SettingsView())
    }
}

// MARK: - Settings

struct SettingsView: View {
    @State private var selectedTab = 0

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 24) {
                SettingsTabButton(title: "General", icon: "gear", isSelected: selectedTab == 0) {
                    selectedTab = 0
                }
                SettingsTabButton(title: "Devices", icon: "iphone", isSelected: selectedTab == 1) {
                    selectedTab = 1
                }
            }
            .padding(.top, 12)
            .padding(.bottom, 8)

            Divider()

            Group {
                if selectedTab == 0 {
                    GeneralSettingsView()
                } else {
                    DevicesSettingsView()
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}

struct SettingsTabButton: View {
    let title: String
    let icon: String
    let isSelected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(spacing: 4) {
                Image(systemName: icon)
                    .font(.system(size: 20))
                Text(title)
                    .font(.caption)
            }
            .frame(width: 64, height: 48)
            .background(isSelected ? Color.accentColor.opacity(0.15) : Color.clear)
            .cornerRadius(8)
        }
        .buttonStyle(.plain)
        .foregroundStyle(isSelected ? .primary : .secondary)
    }
}

struct GeneralSettingsView: View {
    @State private var launchAtLogin = true
    @State private var showNotifications = true

    var body: some View {
        Form {
            Toggle("Launch at Login", isOn: $launchAtLogin)
            Toggle("Show Notifications", isOn: $showNotifications)
        }
        .padding()
    }
}

struct DevicesSettingsView: View {
    var body: some View {
        VStack {
            Spacer()
            Image(systemName: "iphone.slash")
                .font(.system(size: 32))
                .foregroundStyle(.tertiary)
            Text("No paired devices")
                .foregroundStyle(.secondary)
                .padding(.top, 8)
            Text("Use \"Pair New Device\" to connect your iPhone")
                .font(.caption)
                .foregroundStyle(.tertiary)
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }
}

// MARK: - Pairing

private func generateQRCode(from data: Data) -> NSImage? {
    let filter = CIFilter.qrCodeGenerator()
    filter.message = data
    filter.correctionLevel = "M"
    guard let ciImage = filter.outputImage else { return nil }
    let scaled = ciImage.transformed(by: CGAffineTransform(scaleX: 8, y: 8))
    let rep = NSCIImageRep(ciImage: scaled)
    let nsImage = NSImage(size: rep.size)
    nsImage.addRepresentation(rep)
    return nsImage
}

struct PairingView: View {
    @State private var initiator: PairingInitiator?
    @State private var qrImage: NSImage?
    @State private var isPairing = false

    var body: some View {
        VStack(spacing: 20) {
            if let qrImage {
                Image(nsImage: qrImage)
                    .interpolation(.none)
                    .resizable()
                    .frame(width: 200, height: 200)
            } else {
                ProgressView()
                    .frame(width: 200, height: 200)
            }

            Text("Scan with PhantomKey iOS")
                .font(.headline)

            if let code = initiator?.displayCode {
                Text("Confirm this code on your iPhone:")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                Text(code)
                    .font(.system(size: 36, design: .monospaced))
                    .bold()
            }

            if isPairing {
                ProgressView("Pairing...")
            }
        }
        .padding(30)
        .frame(minWidth: 300)
        .onAppear {
            let newInitiator = PairingInitiator()
            initiator = newInitiator
            if let payload = try? newInitiator.qrData.toQRPayload() {
                qrImage = generateQRCode(from: payload)
            }
        }
    }
}
#endif
