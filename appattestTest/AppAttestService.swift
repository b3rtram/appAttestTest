//
//  AppAttestService.swift
//  appattestTest
//
//  Created by Bertram Holzer on 29.11.25.
//

import Foundation
import DeviceCheck
import CryptoKit
import Combine

/// Service class for App Attest - generates attestations and assertions
@MainActor
class AppAttestService: ObservableObject {
    
    // MARK: - Published Properties
    @Published var status: String = "Ready"
    @Published var keyId: String?
    @Published var isAttested: Bool = false
    
    // MARK: - Private Properties
    private let service = DCAppAttestService.shared
    private let keyIdKey = "AppAttestKeyIdentifier"
    
    // MARK: - Initialization
    init() {
        // Check if App Attest is available
        checkAvailability()
        
        // Load saved key ID if available
        loadKeyId()
    }
    
    // MARK: - Availability Check
    private func checkAvailability() {
        if service.isSupported {
            status = "App Attest is supported"
        } else {
            status = "App Attest is NOT supported"
        }
    }
    
    // MARK: - Key Management
    
    /// Loads the saved key ID from UserDefaults
    private func loadKeyId() {
        if let savedKeyId = UserDefaults.standard.string(forKey: keyIdKey) {
            self.keyId = savedKeyId
            self.isAttested = true
            status = "Existing key loaded"
        }
    }
    
    /// Saves the key ID to UserDefaults
    private func saveKeyId(_ keyId: String) {
        UserDefaults.standard.set(keyId, forKey: keyIdKey)
        self.keyId = keyId
        self.isAttested = true
    }
    
    /// Deletes the saved key ID (for testing)
    func resetAttestation() {
        UserDefaults.standard.removeObject(forKey: keyIdKey)
        self.keyId = nil
        self.isAttested = false
        status = "Attestation reset"
    }
    
    // MARK: - Attestation
    
    /// Generiert eine neue App Attestierung
    /// - Parameter serverChallenge: Ein Challenge-String vom Server (Base64)
    /// - Returns: Das Attestierungs-Objekt mit allen relevanten Daten
    func generateAttestation(serverChallenge: String) async throws -> AttestationResult {
        guard service.isSupported else {
            throw AppAttestError.notSupported
        }
        
        print("🔐 === App Attest: Starte Attestierung ===")
        print("📥 Server Challenge (Base64): \(serverChallenge)")
        
        status = "Generiere Key ID..."
        
        // Schritt 1: Generiere eine neue Key ID
        let keyId = try await service.generateKey()
        print("🔑 Key ID generiert: \(keyId)")
        print("   Länge: \(keyId.count) Zeichen")
        status = "Key ID generiert: \(keyId.prefix(8))..."
       
        // Schlüssel aus Secure Enclave abrufen und Public Key extrahieren
        let privateKey = try SecureEnclaveService.shared.retrievePrivateKey(withTag: keyId)
        if let publicKeyData = SecureEnclaveService.shared.getPublicKeyRepresentation(from: privateKey) {
            print("🔓 Public Key Details:")
            print("   Größe: \(publicKeyData.count) Bytes")
            print("   Hex: \(publicKeyData.map { String(format: "%02x", $0) }.joined())")
            print("   Base64: \(publicKeyData.base64EncodedString())")
            
            // Public Key im X9.63 Format (für P-256):
            // Byte 0: 0x04 (unkomprimiert)
            // Bytes 1-32: X-Koordinate
            // Bytes 33-64: Y-Koordinate
            if publicKeyData.count == 65 && publicKeyData[0] == 0x04 {
                let xCoord = publicKeyData[1...32]
                let yCoord = publicKeyData[33...64]
                print("   X-Koordinate: \(xCoord.map { String(format: "%02x", $0) }.joined())")
                print("   Y-Koordinate: \(yCoord.map { String(format: "%02x", $0) }.joined())")
            }
        } else {
            print("⚠️  Public Key konnte nicht extrahiert werden")
        }
        
        // Schritt 2: Hash des Challenge-Strings berechnen
        guard let challengeData = Data(base64Encoded: serverChallenge) else {
            print("❌ Fehler: Challenge ist kein gültiger Base64-String")
            throw AppAttestError.invalidChallenge
        }
        print("📊 Challenge Daten:")
        print("   Größe: \(challengeData.count) Bytes")
        print("   Hex: \(challengeData.map { String(format: "%02x", $0) }.joined())")
        
        let hash = Data(SHA256.hash(data: challengeData))
        print("🔐 SHA256 Hash des Challenge:")
        print("   Größe: \(hash.count) Bytes")
        print("   Hex: \(hash.map { String(format: "%02x", $0) }.joined())")
        print("   Base64: \(hash.base64EncodedString())")
        
        status = "Generiere Attestierung..."
        
        // Schritt 3: Attestierung erstellen
        print("⏳ Rufe service.attestKey auf...")
        let attestation = try await service.attestKey(keyId, clientDataHash: hash)
        print("✅ Attestierung erhalten:")
        print("   Größe: \(attestation.count) Bytes")
        print("   Base64 (erste 100 Zeichen): \(attestation.base64EncodedString().prefix(100))...")
        print("   Base64 (vollständig): \(attestation.base64EncodedString())")
        
        // Schritt 4: Key ID speichern
        saveKeyId(keyId)
        status = "Attestierung erfolgreich generiert!"
        print("💾 Key ID gespeichert in UserDefaults")
        print("🎉 === Attestierung erfolgreich abgeschlossen ===\n")
        
        return AttestationResult(
            keyId: keyId,
            attestation: attestation,
            challenge: serverChallenge
        )
    }
    
    // MARK: - Assertion
    
    /// Generiert eine Assertion für eine Anfrage
    /// - Parameter requestData: Die Daten der Anfrage (z.B. JSON)
    /// - Returns: Das Assertions-Objekt mit allen relevanten Daten
    func generateAssertion(for requestData: Data) async throws -> AssertionResult {
        guard service.isSupported else {
            throw AppAttestError.notSupported
        }
        
        guard let keyId = self.keyId else {
            throw AppAttestError.noKeyAvailable
        }
        
        status = "Generiere Assertion..."
        
        // Hash der Request-Daten berechnen
        let hash = Data(SHA256.hash(data: requestData))
        
        // Assertion generieren
        let assertion = try await service.generateAssertion(keyId, clientDataHash: hash)
        
        status = "Assertion erfolgreich generiert!"
        
        return AssertionResult(
            assertion: assertion,
            requestData: requestData,
            keyId: keyId
        )
    }
    
    /// Convenience-Methode: Generiert eine Assertion für einen String
    /// - Parameter requestString: Der Request als String
    /// - Returns: Das Assertions-Objekt
    func generateAssertion(for requestString: String) async throws -> AssertionResult {
        guard let data = requestString.data(using: .utf8) else {
            throw AppAttestError.invalidRequestData
        }
        return try await generateAssertion(for: data)
    }
}

// MARK: - Result Types

/// Ergebnis einer Attestierung
struct AttestationResult {
    let keyId: String
    let attestation: Data
    let challenge: String
    
    /// Attestierung als Base64-String
    var attestationBase64: String {
        attestation.base64EncodedString()
    }
}

/// Ergebnis einer Assertion
struct AssertionResult {
    let assertion: Data
    let requestData: Data
    let keyId: String
    
    /// Assertion als Base64-String
    var assertionBase64: String {
        assertion.base64EncodedString()
    }
    
    /// Request-Daten als String (falls möglich)
    var requestString: String? {
        String(data: requestData, encoding: .utf8)
    }
}

// MARK: - Error Types

enum AppAttestError: LocalizedError {
    case notSupported
    case noKeyAvailable
    case invalidChallenge
    case invalidRequestData
    
    var errorDescription: String? {
        switch self {
        case .notSupported:
            return "App Attest wird auf diesem Gerät nicht unterstützt"
        case .noKeyAvailable:
            return "Keine Key ID verfügbar. Bitte erst eine Attestierung generieren."
        case .invalidChallenge:
            return "Ungültiger Challenge-String"
        case .invalidRequestData:
            return "Ungültige Request-Daten"
        }
    }
}
