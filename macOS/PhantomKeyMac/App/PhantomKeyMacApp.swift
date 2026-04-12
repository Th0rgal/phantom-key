#if canImport(AppKit)
import SwiftUI
import PhantomKeyCore

@main
struct PhantomKeyMacApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        Settings {
            SettingsView()
        }
    }
}

class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem?
    private var bridgeController: BridgeController?

    func applicationDidFinishLaunching(_ notification: Notification) {
        setupMenuBar()
        bridgeController = BridgeController()
        bridgeController?.start()
    }

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

    @objc private func showPairing() {
        NSApp.activate(ignoringOtherApps: true)
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 400, height: 500),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        window.title = "Pair iPhone"
        window.contentView = NSHostingView(rootView: PairingView())
        window.center()
        window.makeKeyAndOrderFront(nil)
    }

    @objc private func showActivity() {}

    @objc private func showSettings() {
        NSApp.activate(ignoringOtherApps: true)
        NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
    }
}

struct SettingsView: View {
    var body: some View {
        TabView {
            GeneralSettingsView()
                .tabItem { Label("General", systemImage: "gear") }
            DevicesSettingsView()
                .tabItem { Label("Devices", systemImage: "iphone") }
        }
        .frame(width: 450, height: 300)
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
            Text("No paired devices")
                .foregroundStyle(.secondary)
        }
        .padding()
    }
}

struct PairingView: View {
    @State private var pairingCode = ""
    @State private var isPairing = false

    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "qrcode")
                .font(.system(size: 120))
                .foregroundStyle(.secondary)

            Text("Scan with PhantomKey iOS")
                .font(.headline)

            if !pairingCode.isEmpty {
                Text("Confirm this code on your iPhone:")
                    .font(.subheadline)
                Text(pairingCode)
                    .font(.system(size: 36, design: .monospaced))
                    .bold()
            }

            if isPairing {
                ProgressView("Pairing...")
            }
        }
        .padding(30)
        .onAppear {
            pairingCode = PairingKeys.generatePairingCode()
        }
    }
}
#endif
