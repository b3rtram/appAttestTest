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

/// Service-Klasse für App Attest - generiert Attestierungen und Assertionen
@MainActor
class AppAttestService: ObservableObject {
    
    // MARK: - Published Properties
    @Published var status: String = "Bereit"
    @Published var keyId: String?
    @Published var isAttested: Bool = false
    
    // MARK: - Private Properties
    private let service = DCAppAttestService.shared
    private let keyIdKey = "AppAttestKeyIdentifier"
    
    // MARK: - Initialization
    init() {
        // Prüfe ob App Attest verfügbar ist
        checkAvailability()
        
        // Lade gespeicherte Key ID falls vorhanden
        loadKeyId()
    }
    
    // MARK: - Availability Check
    private func checkAvailability() {
        if service.isSupported {
            status = "App Attest wird unterstützt"
        } else {
            status = "App Attest wird NICHT unterstützt"
        }
    }
    
    // MARK: - Key Management
    
    /// Lädt die gespeicherte Key ID aus UserDefaults
    private func loadKeyId() {
        if let savedKeyId = UserDefaults.standard.string(forKey: keyIdKey) {
            self.keyId = savedKeyId
            self.isAttested = true
            status = "Bestehender Key geladen"
        }
    }
    
    /// Speichert die Key ID in UserDefaults
    private func saveKeyId(_ keyId: String) {
        UserDefaults.standard.set(keyId, forKey: keyIdKey)
        self.keyId = keyId
        self.isAttested = true
    }
    
    /// Löscht die gespeicherte Key ID (für Tests)
    func resetAttestation() {
        UserDefaults.standard.removeObject(forKey: keyIdKey)
        self.keyId = nil
        self.isAttested = false
        status = "Attestierung zurückgesetzt"
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
       
        // WICHTIG: Der Public Key ist im Attestation-Objekt enthalten!
        // App Attest Keys können nicht direkt über die Keychain abgerufen werden.
        // Der Public Key wird im attestation statement eingebettet sein.
        
        // https://stackoverflow.com/questions/63186792/using-the-private-key-generated-by-dcappattestservice
        
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
        
        // Schritt 4: Public Key aus Attestation extrahieren (optional)
        if let publicKeyData = extractPublicKey(from: attestation) {
            print("🔓 Public Key aus Attestation extrahiert:")
            print("   Größe: \(publicKeyData.count) Bytes")
            print("   Hex: \(publicKeyData.map { String(format: "%02x", $0) }.joined())")
            print("   Base64: \(publicKeyData.base64EncodedString())")
        }
        
        // Schritt 5: Key ID speichern
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
    
    // MARK: - Helper Methods
    
    /// Extrahiert den Public Key aus einem App Attest Attestation-Objekt
    /// Das Attestation-Objekt ist ein CBOR-kodiertes Objekt im Apple-spezifischen Format
    /// - Parameter attestation: Das Attestation-Objekt
    /// - Returns: Der Public Key als Data, falls gefunden
    private func extractPublicKey(from attestation: Data) -> Data? {
        // Das Attestation-Objekt enthält den Public Key in einem verschachtelten CBOR-Format
        // Für eine vollständige Extraktion wäre ein CBOR-Parser notwendig
        // Dies ist eine vereinfachte Version für Debugging-Zwecke
        
        // Der Public Key (P-256, 65 Bytes im X9.63 Format) ist irgendwo im Attestation eingebettet
        // Suche nach dem typischen Pattern: 0x04 gefolgt von 64 Bytes (X und Y Koordinaten)
        
        let bytes = [UInt8](attestation)
        for i in 0..<(bytes.count - 65) {
            if bytes[i] == 0x04 {
                // Prüfe ob die nächsten 64 Bytes plausibel aussehen
                let potentialKey = attestation.subdata(in: i..<(i + 65))
                // Eine einfache Heuristik: Der Key sollte nicht nur aus Nullen bestehen
                let nonZeroCount = potentialKey.filter { $0 != 0 }.count
                if nonZeroCount > 32 {  // Mindestens die Hälfte sollte nicht-null sein
                    return potentialKey
                }
            }
        }
        
        print("⚠️  Public Key konnte nicht aus Attestation extrahiert werden")
        print("   Hinweis: Verwende einen CBOR-Parser für vollständige Extraktion")
        return nil
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
