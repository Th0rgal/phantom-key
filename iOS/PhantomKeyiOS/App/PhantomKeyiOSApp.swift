#if canImport(UIKit)
import SwiftUI

@main
struct PhantomKeyiOSApp: App {
    @StateObject private var appState = AppState()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(appState)
        }
    }
}

class AppState: ObservableObject {
    @Published var isPaired = false
    @Published var isConnected = false
    @Published var credentials: [CredentialInfo] = []
    @Published var pendingRequest: SigningRequest?
}

struct CredentialInfo: Identifiable {
    let id: String
    let relyingPartyName: String
    let userName: String
    let createdAt: Date
    let lastUsed: Date?
    let signCount: Int
}

struct SigningRequest: Identifiable {
    let id: String
    let relyingPartyId: String
    let relyingPartyName: String
    let action: String
    let timestamp: Date
}

struct ContentView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        NavigationStack {
            if !appState.isPaired {
                PairingScanView()
            } else {
                MainDashboardView()
            }
        }
    }
}

struct PairingScanView: View {
    @EnvironmentObject var appState: AppState
    @State private var isScanning = false

    var body: some View {
        VStack(spacing: 30) {
            Spacer()

            Image(systemName: "key.radiowaves.forward")
                .font(.system(size: 80))
                .foregroundStyle(.blue)

            Text("PhantomKey")
                .font(.largeTitle.bold())

            Text("Scan the QR code on your Mac to pair")
                .font(.body)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            Button(action: { isScanning = true }) {
                Label("Scan QR Code", systemImage: "qrcode.viewfinder")
                    .font(.headline)
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(.blue)
                    .foregroundStyle(.white)
                    .clipShape(RoundedRectangle(cornerRadius: 12))
            }
            .padding(.horizontal, 40)

            Spacer()
        }
        .navigationTitle("Setup")
    }
}

struct MainDashboardView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        List {
            Section {
                HStack {
                    Image(systemName: appState.isConnected ? "checkmark.circle.fill" : "circle.dotted")
                        .foregroundStyle(appState.isConnected ? .green : .orange)
                    Text(appState.isConnected ? "Connected to Mac" : "Searching for Mac...")
                }
            }

            Section("Credentials") {
                if appState.credentials.isEmpty {
                    Text("No credentials yet")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(appState.credentials) { cred in
                        NavigationLink(destination: CredentialDetailView(credential: cred)) {
                            VStack(alignment: .leading) {
                                Text(cred.relyingPartyName)
                                    .font(.headline)
                                Text(cred.userName)
                                    .font(.subheadline)
                                    .foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }

            Section {
                NavigationLink(destination: PolicySettingsView()) {
                    Label("Security Policies", systemImage: "shield.checkered")
                }
                NavigationLink(destination: ActivityLogView()) {
                    Label("Activity Log", systemImage: "list.bullet.rectangle")
                }
            }
        }
        .navigationTitle("PhantomKey")
    }
}

struct CredentialDetailView: View {
    let credential: CredentialInfo

    var body: some View {
        List {
            Section("Details") {
                LabeledContent("Site", value: credential.relyingPartyName)
                LabeledContent("User", value: credential.userName)
                LabeledContent("Created", value: credential.createdAt.formatted())
                LabeledContent("Sign Count", value: "\(credential.signCount)")
            }

            Section {
                Button("Delete Credential", role: .destructive) {}
            }
        }
        .navigationTitle(credential.relyingPartyName)
    }
}

struct PolicySettingsView: View {
    @State private var defaultAction = "Always Ask"
    @State private var maxPerMinute = 10
    @State private var autoLockTimeout = 300

    var body: some View {
        Form {
            Section("Default Behavior") {
                Picker("Default Action", selection: $defaultAction) {
                    Text("Always Ask").tag("Always Ask")
                    Text("Auto-Approve (5 min)").tag("Auto-Approve")
                    Text("Deny").tag("Deny")
                }
            }

            Section("Rate Limiting") {
                Stepper("Max \(maxPerMinute)/min", value: $maxPerMinute, in: 1...60)
            }

            Section("Security") {
                Picker("Auto-Lock", selection: $autoLockTimeout) {
                    Text("1 minute").tag(60)
                    Text("5 minutes").tag(300)
                    Text("15 minutes").tag(900)
                    Text("Never").tag(0)
                }
            }
        }
        .navigationTitle("Security Policies")
    }
}

struct ActivityLogView: View {
    var body: some View {
        List {
            Text("No activity yet")
                .foregroundStyle(.secondary)
        }
        .navigationTitle("Activity Log")
    }
}

struct ApprovalSheetView: View {
    let request: SigningRequest
    let onApprove: () -> Void
    let onDeny: () -> Void

    var body: some View {
        VStack(spacing: 20) {
            Image(systemName: "key.fill")
                .font(.system(size: 50))
                .foregroundStyle(.blue)

            Text("Sign-in Request")
                .font(.title2.bold())

            VStack(spacing: 8) {
                Text(request.relyingPartyName)
                    .font(.headline)
                Text(request.action)
                    .foregroundStyle(.secondary)
            }

            HStack(spacing: 16) {
                Button(action: onDeny) {
                    Text("Deny")
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(.red.opacity(0.1))
                        .foregroundStyle(.red)
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                }

                Button(action: onApprove) {
                    Text("Approve")
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(.blue)
                        .foregroundStyle(.white)
                        .clipShape(RoundedRectangle(cornerRadius: 12))
                }
            }
            .padding(.horizontal)
        }
        .padding(30)
    }
}
#endif
