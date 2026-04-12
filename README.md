# PhantomKey

A software-based security key system where macOS exposes a virtual FIDO2/WebAuthn authenticator to applications, while an iPhone app securely holds the cryptographic keys and enforces customizable signing policies.

## How It Works

```
Browser/SSH (Mac) → Virtual FIDO Device → BLE → iPhone → Secure Enclave → Signed Response
```

1. **Mac** presents a virtual HID security key (usage page 0xF1D0) via DriverKit
2. When a browser or SSH client sends a FIDO2/CTAP2 request, the Mac app forwards it to the paired iPhone over an encrypted BLE channel
3. **iPhone** evaluates the request against configurable policies (auto-approve, deny, time windows, rate limits)
4. If approved (automatically or via Face ID/Touch ID), the iPhone signs with a Secure Enclave P-256 key and returns the response
5. The Mac delivers the signed response back to the requesting application

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full system design, security model, and protocol specification.

## Project Structure

```
phantom-key/
├── Package.swift                    # Swift Package (Core library)
├── Sources/PhantomKeyCore/          # Cross-platform core (builds on Linux)
│   ├── CTAP/                        # CTAP2 protocol, CBOR, HID framing
│   ├── Crypto/                      # P-256, Ed25519, X25519, AES-GCM
│   ├── Transport/                   # Encrypted message envelopes, pairing
│   └── Policy/                      # Rule engine, per-site policies
├── Tests/PhantomKeyCoreTests/       # Full test suite (runs on Linux)
├── macOS/PhantomKeyMac/             # macOS menu bar app
│   ├── App/                         # SwiftUI app, settings
│   ├── HID/                         # Virtual FIDO HID device (DriverKit)
│   └── Bridge/                      # BLE Central, connects to iPhone
└── iOS/PhantomKeyiOS/               # iOS app
    ├── App/                         # SwiftUI app, dashboard, policies
    ├── KeyStore/                    # Secure Enclave key management
    └── Bridge/                      # BLE Peripheral, serves Mac requests
```

## Building

### Core Library (Linux or macOS)

```bash
swift build
swift test
```

The core library contains all protocol logic, cryptography, and the policy engine. It builds and tests fully on Linux using swift-crypto (BoringSSL backend).

### macOS App

Requires Xcode 16+ on macOS 15+. Open `macOS/PhantomKeyMac.xcodeproj` and build, or:

```bash
xcodebuild build -project macOS/PhantomKeyMac.xcodeproj -scheme PhantomKeyMac
```

### iOS App

Requires Xcode 16+ with iOS 17+ SDK:

```bash
xcodebuild build -project iOS/PhantomKeyiOS.xcodeproj -scheme PhantomKeyiOS \
  -destination 'platform=iOS Simulator,name=iPhone 16'
```

## Security Properties

- Private keys never leave the iPhone's Secure Enclave
- Mac is a relay only — no key material touches the Mac
- All Mac↔iPhone communication encrypted with AES-256-GCM
- Key exchange via X25519 with visual pairing code verification
- Biometric gating (Face ID/Touch ID) for signing operations
- Per-relying-party policies with rate limiting

## Communication Channels

| Channel | Role | Latency | Background iOS |
|---------|------|---------|---------------|
| Core Bluetooth | Primary | 15-50ms | Yes |
| Bonjour/TCP | Fallback (same WiFi) | <10ms | Limited |
| QR Code | Initial pairing only | N/A | N/A |

## SSH Usage

With the virtual HID device active, OpenSSH discovers PhantomKey automatically:

```bash
# Generate a FIDO2 resident key (triggers iPhone approval)
ssh-keygen -t ecdsa-sk -O resident

# SSH authentication (triggers iPhone approval or auto-approve)
ssh user@host
```

## Policy Examples

- **Always ask**: Require Face ID for every signing (default)
- **Auto-approve 5 min**: After one Face ID approval, auto-approve for 5 minutes
- **Deny**: Block all requests from a specific site
- **Time window**: Only allow signing during work hours (9am-6pm)
- **Rate limit**: Max 10 signatures per minute globally

## License

MIT
