//
//  SecureEnclaveManager.swift
//  PasskeyGuard
//
//  Created by Alexander Friedl on 26.05.25.
//

import CryptoKit
import Foundation
import AuthenticationServices
import Security
import LocalAuthentication
import OSLog

enum RandomError: Error {
    case generationFailed(OSStatus)
}

public class SecureEnclaveService {
   
    static let shared = SecureEnclaveService()

    let log = Logger(subsystem: "com.emdgroup.PasskeyGuard", category: "SecureEnclaveService")
    
    private init() {}
    
    public func generateCredentialID() -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else { fatalError("Error generating credential ID") }
        return Data(bytes)
    }
    
    func isKeyInSecureEnclave(_ privateKey: SecKey) -> Bool {
        if let attributes = SecKeyCopyAttributes(privateKey) as? [String: Any],
           let tokenID = attributes[kSecAttrTokenID as String] as? String {
            return tokenID == (kSecAttrTokenIDSecureEnclave as String)
        }
        return false
    }
    
    public func getAllKeysInSecureEnclave() {
        
        let query: [String: Any] = [
          kSecClass as String: kSecClassKey,
          kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
          kSecReturnAttributes as String: true,
          kSecMatchLimit as String: kSecMatchLimitAll
        ]
        var result: CFTypeRef?
        SecItemCopyMatching(query as CFDictionary, &result)
        if let items = result as? [[String: Any]] {
            for attrs in items {
                for (key, value) in attrs {
                    if key == kSecAttrApplicationTag as String {
                        let tagString = value as? String
                        
                        log.info("\(key): \(tagString!)")
                    }
                }
            }
        }
    }
    
    public func retrievePrivateKey(withTag tag: String) throws -> SecKey {
        guard let tagData = tag.data(using: .utf8) else {
            throw NSError(domain: "KeyRetrieval", code: -1, userInfo: [NSLocalizedDescriptionKey: NSLocalizedString("invalid_tag", comment: "Invalid tag error message")])
        }
        
        let laContext = LAContext()
        laContext.localizedReason = NSLocalizedString("biometric_reason_key_loading", comment: "Biometric authentication reason for key loading")
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tagData,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
            kSecUseAuthenticationContext as String: laContext
        ]
        
        var item: CFTypeRef?
        let state = SecItemCopyMatching(query as CFDictionary, &item)
        guard state == errSecSuccess, let privateKey = item as! SecKey? else {
            let errorMessage = SecCopyErrorMessageString(state, nil) as String? ?? "Unbekannter Fehler"
            log.error("Error getting the private key: \(errorMessage) (state: \(state))")
            throw NSError(domain: "KeyRetrieval", code: Int(state), userInfo: [NSLocalizedDescriptionKey: errorMessage])
        }

        if isKeyInSecureEnclave(privateKey as SecKey) {
            log.info("Private key is in private enclave")
        } else {
            log.info("Private key is not in secure enclave")
        }
        
        return privateKey
    }
    
    public func signData(privateKey: SecKey, data: Data) throws -> Data {
        
        let algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256
        
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
            throw NSError(domain: "SignError", code: -1, userInfo: [NSLocalizedDescriptionKey: NSLocalizedString("algorithm_not_supported", comment: "Algorithm not supported error message")])
        }
        
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(privateKey, algorithm, data as CFData, &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }
        
        return signature
    }

    public func deletePrivateKey(tag: String) -> Bool {
        guard let tagData = tag.data(using: .utf8) else { return false }
            
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tagData,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom
        ]
        
        // Lösche den Schlüssel.
        let status = SecItemDelete(query as CFDictionary)
        if status == errSecSuccess || status == errSecItemNotFound {
            // Entweder wurde der Schlüssel erfolgreich gelöscht,
            // oder er existierte nicht.
            return true
        } else {
            log.error("\(NSLocalizedString("key_deletion_error", comment: "Key deletion error message")): \(status)")
            return false
        }
    }
    
    public func createPrivateKey(keyTag: String) throws -> SecKey {
       // Create access control that supports both biometrics and device passcode fallback
       let access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                     kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                     [.privateKeyUsage, .biometryAny, .or, .devicePasscode],
                                                     nil)!
        
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrApplicationTag as String: keyTag,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrAccessControl as String: access
            ]
        ]
        
        var error: Unmanaged<CFError>?
        guard let secKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        
        return secKey
    }
    
    public func getPublicKeyRepresentation(from privateKey: SecKey) -> Data? {
        
        // Extrahiere den öffentlichen Schlüssel
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            print(NSLocalizedString("public_key_retrieval_error", comment: "Public key retrieval error message"))
            return nil
        }
        
        // Konvertiere den öffentlichen Schlüssel in Base64 für die Anzeige
        var errorExport: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &errorExport) as Data? else {
            print(NSLocalizedString("public_key_export_error", comment: "Public key export error message") + ": \(errorExport!.takeRetainedValue())")
            return nil
        }
        
        return publicKeyData
    }
    
    public func deleteKeys(withPrefix prefix: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        var result: CFTypeRef?
        SecItemCopyMatching(query as CFDictionary, &result)
        guard let items = result as? [[String: Any]] else { return false }
        for attrs in items {
            
            for (key, value) in attrs {
                if key == kSecAttrApplicationTag as String {
                    let tag = value as? String
                    
                    if tag!.hasPrefix(prefix) {
                        let deleteQuery: [String: Any] = [
                            kSecClass as String: kSecClassKey,
                            kSecAttrApplicationTag as String: tag!,
                            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
                        ]

                        let status: OSStatus = SecItemDelete(deleteQuery as CFDictionary) as OSStatus
                        
                        if let message = SecCopyErrorMessageString(status, nil) as String? {
                            log.error("Error Message: \(message)")
                        } else {
                            log.error("Unbekannter Fehlercode: \(status)")
                        }
                    }
                }
            }

            
        }
        
        return true
    }
}
