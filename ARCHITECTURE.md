# PhantomKey Architecture

**A software-based security key where macOS emulates a FIDO2/WebAuthn authenticator and an iPhone app holds the keys.**

## Overview

```
┌─────────────────────────────────────────────────────────────────┐
│  macOS                                                          │
│                                                                 │
│  ┌──────────┐    CTAP2/HID     ┌──────────────────────┐        │
│  │ Browser  │ ──────────────── │  PhantomKey Mac       │        │
│  │ SSH      │                  │  (Menu Bar App)       │        │
│  │ Any FIDO │                  │                       │        │
│  │ Client   │                  │  • Virtual HID Device │        │
│  └──────────┘                  │    (DriverKit)        │        │
│                                │  • CTAP2 Responder    │        │
│                                │  • BLE Central        │        │
│                                │  • Bonjour Client     │        │
│                                └─────────┬────────────┘        │
│                                          │                      │
└──────────────────────────────────────────┼──────────────────────┘
                                           │
                          Core Bluetooth    │  Encrypted Channel
                          (primary)        │  (X25519 + AES-GCM)
                          Bonjour/TCP      │
                          (fallback)       │
                                           │
┌──────────────────────────────────────────┼──────────────────────┐
│  iOS                                     │                      │
│                                ┌─────────┴────────────┐        │
│                                │  PhantomKey iOS       │        │
│                                │                       │        │
│                                │  • Secure Enclave     │        │
│                                │    Key Storage        │        │
│                                │  • Policy Engine      │        │
│                                │  • BLE Peripheral     │        │
│                                │  • Bonjour Server     │        │
│                                │  • Face ID / Touch ID │        │
│                                └───────────────────────┘        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Components

### 1. Shared Core (`PhantomKeyCore` Swift Package)

Cross-platform library that builds and tests on Linux, macOS, and iOS.

| Module | Purpose |
|--------|---------|
| `CTAP` | CTAP2 command parsing, CBOR encoding/decoding, authenticator state machine |
| `Crypto` | P-256/Ed25519 key operations, X25519 key exchange, AES-GCM encryption |
| `Transport` | Message framing, request/response envelopes, channel abstraction |
| `Policy` | Rule engine: auto-approve timers, per-relying-party rules, rate limiting |

### 2. macOS App (`PhantomKeyMac`)

Menu bar application that presents a virtual FIDO2 authenticator to the system.

**Virtual HID Device (DriverKit)**
- Registers as a HID device on usage page `0xF1D0` (FIDO Alliance)
- Chrome, Firefox, Safari, and OpenSSH/libfido2 discover it automatically
- Receives CTAP2 commands via 64-byte HID reports
- System extension requires notarization and user approval in System Settings

**Bridge Layer**
- Decodes incoming CTAP2 requests (MakeCredential, GetAssertion, GetInfo)
- Forwards signing requests to iPhone over encrypted channel
- Returns signed responses back through the HID interface
- Handles CTAPHID_KEEPALIVE while waiting for iPhone response

**Communication (Central)**
- BLE Central: scans for PhantomKey BLE peripheral service
- Bonjour Client: discovers PhantomKey TCP service on local network
- QR Code Display: shows pairing QR for initial setup

### 3. iOS App (`PhantomKeyiOS`)

Secure key custodian and policy enforcer.

**Key Storage**
- All credential private keys generated in and never leave the Secure Enclave
- Uses `kSecAttrTokenIDSecureEnclave` with P-256 (secp256r1)
- Credential metadata (relying party, user handle, creation date) in encrypted Core Data store
- Master encryption key protected by device passcode + biometric

**Policy Engine**
- Per-relying-party rules:
  - `always_ask`: require biometric for every signing (default)
  - `auto_approve`: approve silently for a configurable duration (e.g., 5 minutes)
  - `deny`: block all requests from this relying party
  - `time_window`: only allow during specific hours
- Global rate limiting: max N signatures per minute
- Notification on every signing operation (even auto-approved)

**Communication (Peripheral)**
- BLE Peripheral: advertises PhantomKey GATT service
- Bonjour Server: listens on local network as fallback
- Background execution: BLE peripheral mode works in iOS background

## Communication Protocol

### Pairing (One-Time Setup)

```
Mac                                    iPhone
 │                                       │
 │  1. Display QR Code containing:       │
 │     • Mac's X25519 public key         │
 │     • Random pairing code (6 digits)  │
 │     • BLE service UUID                │
 │                                       │
 │  2. ─── User scans QR ─────────────►  │
 │                                       │
 │  3. ◄── BLE connection ─────────────  │
 │     iPhone sends its X25519 pub key   │
 │                                       │
 │  4. Both derive shared secret via     │
 │     X25519 + HKDF-SHA256              │
 │                                       │
 │  5. Mac displays pairing code         │
 │     iPhone displays pairing code      │
 │     User confirms they match          │
 │                                       │
 │  6. Pairing complete. Store shared    │
 │     secret in Keychain on both sides  │
 │                                       │
```

### Runtime (Signing Request)

```
Browser/SSH          Mac App              iPhone App
    │                   │                     │
    │  CTAP2 Request    │                     │
    │ ────────────────► │                     │
    │                   │  Encrypted Request  │
    │                   │ ──────────────────► │
    │                   │                     │ Policy
    │                   │                     │ Check
    │  CTAPHID_KEEPALIVE│                     │   │
    │ ◄──────────────── │                     │   ▼
    │                   │                     │ [Auto-approve?]
    │                   │                     │   │ Yes ──► Sign
    │                   │                     │   │ No  ──► Prompt
    │                   │                     │             User
    │                   │                     │             (Face ID)
    │                   │                     │               │
    │                   │  Encrypted Response │               │
    │                   │ ◄────────────────── │ ◄─────────────┘
    │  CTAP2 Response   │                     │
    │ ◄──────────────── │                     │
    │                   │                     │
```

### Message Envelope

All messages between Mac and iPhone are CBOR-encoded and encrypted:

```
┌──────────────────────────────────────┐
│  Encrypted Envelope                  │
│  ┌────────────────────────────────┐  │
│  │ Nonce (12 bytes)               │  │
│  │ Ciphertext (AES-256-GCM)      │  │
│  │  ┌──────────────────────────┐  │  │
│  │  │ version: UInt8           │  │  │
│  │  │ type: RequestType        │  │  │
│  │  │ sequence: UInt32         │  │  │
│  │  │ payload: CBOR Data       │  │  │
│  │  └──────────────────────────┘  │  │
│  │ Auth Tag (16 bytes)            │  │
│  └────────────────────────────────┘  │
└──────────────────────────────────────┘
```

## Security Model

### Threat Model

| Threat | Mitigation |
|--------|------------|
| BLE eavesdropping | All payloads encrypted with AES-256-GCM; shared secret from X25519 key exchange |
| Rogue Mac impersonation | Pairing requires physical QR scan + visual code confirmation |
| Stolen iPhone | Keys in Secure Enclave, require biometric or passcode to sign |
| Replay attacks | Sequence numbers + nonces in every message; CTAP2 challenge includes server nonce |
| Man-in-the-middle | X25519 key exchange with visual confirmation code (SAS) |
| Malware on Mac | Mac never holds private keys; it's a relay only |

### Key Properties

1. **Private keys never leave the iPhone's Secure Enclave** — the Mac is a dumb pipe
2. **No cloud dependency** — works offline, no Apple ID needed for BLE
3. **Biometric gating** — policy engine controls when signing happens
4. **Forward secrecy** — session keys rotated periodically via ratchet

## SSH Integration

OpenSSH 8.2+ supports FIDO2 keys via libfido2. The virtual HID device is discovered
automatically. Workflow:

```bash
# Generate a key (triggers MakeCredential → iPhone approval)
ssh-keygen -t ecdsa-sk -O resident

# Use the key (triggers GetAssertion → iPhone approval or auto-approve)
ssh user@host
```

## File Structure

```
phantom-key/
├── Package.swift                    # SPM manifest for Core
├── Sources/
│   └── PhantomKeyCore/
│       ├── CTAP/                    # CTAP2 protocol
│       │   ├── CTAPCommand.swift
│       │   ├── CTAPAuthenticator.swift
│       │   ├── CBOR.swift
│       │   └── HIDMessage.swift
│       ├── Crypto/                  # Cross-platform crypto
│       │   ├── KeyPair.swift
│       │   ├── ChannelCrypto.swift
│       │   └── Attestation.swift
│       ├── Transport/               # Mac ↔ iPhone messaging
│       │   ├── Envelope.swift
│       │   ├── TransportChannel.swift
│       │   └── PairingProtocol.swift
│       └── Policy/                  # Rule engine
│           ├── PolicyEngine.swift
│           ├── PolicyRule.swift
│           └── PolicyStore.swift
├── Tests/
│   └── PhantomKeyCoreTests/
│       ├── CTAPTests.swift
│       ├── CBORTests.swift
│       ├── CryptoTests.swift
│       ├── PolicyTests.swift
│       └── TransportTests.swift
├── macOS/                           # Xcode project
│   └── PhantomKeyMac/
│       ├── App/
│       ├── HID/
│       └── Bridge/
├── iOS/                             # Xcode project
│   └── PhantomKeyiOS/
│       ├── App/
│       ├── KeyStore/
│       └── Bridge/
├── .github/
│   └── workflows/
│       └── ci.yml
└── ARCHITECTURE.md
```

## Build Strategy

| Target | Environment | What Builds |
|--------|------------|-------------|
| `swift build` | Linux | Core library only |
| `swift test` | Linux | All Core tests |
| `xcodebuild` | macOS | Core + Mac app + iOS app |
| GitHub Actions | Linux runner | Core build + tests |
| GitHub Actions | macOS runner | Full Xcode build |

## Realistic Assessment

**What works today:**
- Core crypto and protocol logic: fully functional cross-platform
- CTAP2 protocol implementation: standards-compliant
- Policy engine: fully testable on any platform
- BLE communication: proven pattern (many apps do this)
- Secure Enclave key storage: well-documented Apple API

**What requires significant effort:**
- DriverKit virtual HID device: requires Apple Developer Program, notarization, system extension approval. This is the hardest part of the system.
- iOS background BLE: works but requires careful state management
- Browser compatibility: each browser has quirks with CTAP2 transports

**Alternative to DriverKit (simpler path):**
- Implement as an SSH agent only (no browser FIDO) via `SSH_AUTH_SOCK`
- Use the CTAP2 hybrid/caBLE transport (BLE advertisement → HTTPS tunnel)
- Provide a browser extension that intercepts WebAuthn calls
