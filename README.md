# App Attest Test

A comprehensive iOS test application demonstrating Apple's **App Attest** framework for secure device and app authentication.

## Overview

This project provides a complete implementation and testing environment for Apple's App Attest service, which allows iOS apps to prove their authenticity to backend servers. App Attest generates cryptographic attestations that verify an app is running on a genuine Apple device and hasn't been tampered with.

## Features

### 🔐 Core Functionality

- **Attestation Generation**: Create cryptographic attestations that prove app authenticity
- **Assertion Generation**: Generate signed assertions for secure API requests
- **Key Management**: Automatic key generation and secure storage in the Secure Enclave
- **Detailed Logging**: Comprehensive debug output for all cryptographic operations

### 🛠️ Technical Implementation

- **App Attest Service** (`AppAttestService.swift`): Complete wrapper around `DCAppAttestService`
  - Key generation and management
  - Attestation creation with server challenge validation
  - Assertion generation for authenticated requests
  - Persistent key storage using UserDefaults
  - Detailed logging of all cryptographic operations (hex, base64, byte sizes)

- **Secure Enclave Integration** (`SecureEnclave.swift`): Utility service for Secure Enclave operations
  - Private key management with biometric protection
  - Public key extraction and representation
  - ECDSA signature generation
  - Key retrieval and deletion operations

- **SwiftUI Interface** (`ContentView.swift`): Interactive testing UI
  - Visual status indicators
  - Step-by-step attestation workflow
  - Result display with copyable data
  - Reset functionality for testing

## How App Attest Works

### 1. Attestation Flow

```
Client (iOS App)          Server
     |                      |
     |-- Request Challenge--|
     |                      |
     |<---- Challenge ------|
     |                      |
  Generate Key              |
  Hash Challenge            |
  Create Attestation        |
     |                      |
     |-- Send Attestation ->|
     |                      |
     |                   Validate
     |                   Store Public Key
     |                      |
     |<---- Success --------|
```

### 2. Assertion Flow

```
Client (iOS App)          Server
     |                      |
  Prepare Request           |
  Hash Request Data         |
  Create Assertion          |
     |                      |
     |-- Request + Assert ->|
     |                      |
     |                   Validate Signature
     |                   Process Request
     |                      |
     |<---- Response -------|
```

## Requirements

- **iOS 14.0+** (App Attest framework availability)
- **Physical iOS Device** (App Attest is not available in Simulator)
- **Xcode 15.0+**
- **Swift 5.9+**

⚠️ **Important**: App Attest **only works on physical devices**. The Simulator will return `isSupported = false`.

## Usage

### Basic Attestation

```swift
let attestService = AppAttestService()

// Generate attestation with server challenge
let challenge = "BASE64_ENCODED_SERVER_CHALLENGE"
let result = try await attestService.generateAttestation(serverChallenge: challenge)

print("Key ID: \(result.keyId)")
print("Attestation: \(result.attestationBase64)")
```

### Generate Assertion

```swift
// Create assertion for API request
let requestData = """
{
    "user_id": "12345",
    "action": "purchase"
}
"""

let assertion = try await attestService.generateAssertion(for: requestData)
print("Assertion: \(assertion.assertionBase64)")
```

### Reset for Testing

```swift
// Clear stored key and reset state
attestService.resetAttestation()
```

## Logging Output

The service provides detailed logging for debugging:

```
🔐 === App Attest: Starte Attestierung ===
📥 Server Challenge (Base64): aGVsbG93b3JsZA==
🔑 Key ID generiert: ABC123DEF456...
   Länge: 43 Zeichen
📊 Challenge Daten:
   Größe: 32 Bytes
   Hex: 68656c6c6f776f726c64...
🔐 SHA256 Hash des Challenge:
   Größe: 32 Bytes
   Hex: 2cf24dba5fb0a30e...
   Base64: LPJNul+wow4=...
⏳ Rufe service.attestKey auf...
✅ Attestierung erhalten:
   Größe: 2841 Bytes
   Base64 (vollständig): o2NmbXRvYXBwbGU...
💾 Key ID gespeichert in UserDefaults
🎉 === Attestierung erfolgreich abgeschlossen ===
```

## Architecture

### Components

```
┌─────────────────────────────────────────┐
│          ContentView (SwiftUI)          │
│  - User Interface                       │
│  - Action Handlers                      │
└─────────────┬───────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│     AppAttestService (@MainActor)       │
│  - Attestation Generation               │
│  - Assertion Generation                 │
│  - Key Management                       │
│  - State Management (@Published)        │
└─────────────┬───────────────────────────┘
              │
              ├──────────────┬─────────────┐
              ▼              ▼             ▼
    ┌─────────────┐  ┌──────────────┐  ┌──────────────┐
    │ DeviceCheck │  │  CryptoKit   │  │ UserDefaults │
    │ Framework   │  │  (SHA256)    │  │  (Storage)   │
    └─────────────┘  └──────────────┘  └──────────────┘
```

### Data Flow

1. **User Action** → ContentView triggers attestation/assertion
2. **Service Layer** → AppAttestService coordinates operation
3. **Framework** → DCAppAttestService handles cryptography
4. **Storage** → Key ID persisted in UserDefaults
5. **Result** → Returned to UI for display

## Security Considerations

### ✅ What App Attest Provides

- **Device Authenticity**: Proves app runs on genuine Apple hardware
- **App Integrity**: Verifies app hasn't been tampered with
- **Non-Repudiation**: Cryptographic proof of requests
- **Secure Enclave**: Private keys never leave the device

### ⚠️ What You Must Do

- **Server Validation**: Always validate attestations and assertions server-side
- **Challenge Freshness**: Use unique, time-limited challenges
- **Key Rotation**: Implement key rotation policies
- **Rate Limiting**: Protect against replay attacks
- **Fraud Detection**: Combine with additional fraud prevention measures

### 🔒 Best Practices

1. **Never trust client-side validation alone**
2. **Validate attestation receipts with Apple's servers**
3. **Store public keys securely on your backend**
4. **Implement proper challenge generation** (cryptographically random, sufficient entropy)
5. **Monitor for suspicious patterns** (e.g., key reuse, rapid regeneration)

## Known Limitations

- ❌ **Simulator Not Supported**: Must test on physical device
- ❌ **iOS 14+ Only**: Older devices cannot use App Attest
- ⚠️ **Key Accessibility**: Private keys managed by system, not directly accessible
- ⚠️ **Public Key Extraction**: Public key embedded in attestation (CBOR format), requires parsing
- ⚠️ **Network Required**: Initial attestation validation requires server communication

## Server-Side Validation

This repository focuses on the **client-side** implementation. For production use, you must implement **server-side validation**:

### Attestation Validation

1. Verify the attestation format (CBOR)
2. Extract and validate the X.509 certificate chain
3. Verify certificate signatures up to Apple's root CA
4. Extract the public key from the attestation
5. Verify the authenticator data
6. Check the challenge hash matches your server's challenge
7. Validate the app ID matches your app's identifier
8. Store the public key for future assertion validation

### Assertion Validation

1. Retrieve the stored public key for the key ID
2. Verify the assertion signature using the public key
3. Validate the authenticator data counter (prevents replay)
4. Hash the request data and verify it matches the assertion
5. Check timestamp/freshness
6. Process the authenticated request

## References

- [Apple App Attest Documentation](https://developer.apple.com/documentation/devicecheck/establishing_your_app_s_integrity)
- [WWDC: Safeguard your app with App Attest](https://developer.apple.com/videos/play/wwdc2021/10244/)
- [DeviceCheck Framework](https://developer.apple.com/documentation/devicecheck)
- [App Attest Server Guide](https://developer.apple.com/documentation/devicecheck/validating_apps_that_connect_to_your_server)

## License

This is a test/demonstration project. Use at your own risk. Ensure proper security auditing before production use.

## Contributing

This is a test project for learning and demonstration purposes. Feel free to fork and experiment!

## Author

Created by Bertram Holzer (29.11.2025)

---

**⚠️ Security Notice**: This code is for testing and educational purposes. Always implement proper server-side validation and follow Apple's security guidelines for production applications.
