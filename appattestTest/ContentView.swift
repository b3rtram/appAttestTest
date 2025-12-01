//
//  ContentView.swift
//  appattestTest
//
//  Created by Bertram Holzer on 29.11.25.
//

import SwiftUI
import CryptoKit

struct ContentView: View {
    @StateObject private var attestService = AppAttestService()
    @State private var attestationResult: AttestationResult?
    @State private var assertionResult: AssertionResult?
    @State private var errorMessage: String?
    @State private var showingAlert = false
    
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 20) {
                    // Status-Anzeige
                    StatusCard(status: attestService.status)
                    
                    // Key ID Anzeige
                    if let keyId = attestService.keyId {
                        InfoCard(title: "Key ID", content: keyId, icon: "key.fill")
                    }
                    
                    // Attestierung
                    VStack(spacing: 12) {
                        Text("1. Attestierung generieren")
                            .font(.headline)
                        
                        Button {
                            Task {
                                await generateAttestation()
                            }
                        } label: {
                            Label("App Attestierung erstellen", systemImage: "checkmark.shield.fill")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(!attestService.isAttested && attestService.keyId != nil)
                        
                        if let result = attestationResult {
                            AttestationResultView(result: result)
                        }
                    }
                    .padding()
                    .background(Color(.secondarySystemBackground))
                    .cornerRadius(12)
                    
                    // Assertion
                    VStack(spacing: 12) {
                        Text("2. Assertion generieren")
                            .font(.headline)
                        
                        Button {
                            Task {
                                await generateAssertion()
                            }
                        } label: {
                            Label("Assertion erstellen", systemImage: "signature")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.bordered)
                        .disabled(!attestService.isAttested)
                        
                        if let result = assertionResult {
                            AssertionResultView(result: result)
                        }
                    }
                    .padding()
                    .background(Color(.secondarySystemBackground))
                    .cornerRadius(12)
                    
                    // Reset Button
                    Button(role: .destructive) {
                        attestService.resetAttestation()
                        attestationResult = nil
                        assertionResult = nil
                    } label: {
                        Label("Attestierung zurücksetzen", systemImage: "arrow.counterclockwise")
                    }
                    .buttonStyle(.bordered)
                }
                .padding()
            }
            .navigationTitle("App Attest Test")
            .alert("Fehler", isPresented: $showingAlert) {
                Button("OK") {
                    errorMessage = nil
                }
            } message: {
                if let error = errorMessage {
                    Text(error)
                }
            }
        }
    }
    
    // MARK: - Actions
    
    private func generateAttestation() async {
        do {
            // Generiere einen simulierten Server-Challenge (Base64)
            let challenge = generateRandomChallenge()
            let result = try await attestService.generateAttestation(serverChallenge: challenge)
            attestationResult = result
        } catch {
            errorMessage = error.localizedDescription
            showingAlert = true
        }
    }
    
    private func generateAssertion() async {
        do {
            // Beispiel-Request-Daten
            let requestData = """
            {
                "user_id": "12345",
                "action": "purchase",
                "timestamp": "\(Date().timeIntervalSince1970)"
            }
            """
            let result = try await attestService.generateAssertion(for: requestData)
            assertionResult = result
        } catch {
            errorMessage = error.localizedDescription
            showingAlert = true
        }
    }
    
    private func generateRandomChallenge() -> String {
        // Generiere 32 zufällige Bytes als Challenge
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes).base64EncodedString()
    }
}

// MARK: - Supporting Views

struct StatusCard: View {
    let status: String
    
    var body: some View {
        HStack {
            Image(systemName: "info.circle.fill")
                .foregroundStyle(.blue)
            Text(status)
                .font(.subheadline)
            Spacer()
        }
        .padding()
        .background(Color(.systemBackground))
        .cornerRadius(12)
        .shadow(radius: 2)
    }
}

struct InfoCard: View {
    let title: String
    let content: String
    let icon: String
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(title, systemImage: icon)
                .font(.headline)
            Text(content)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .lineLimit(2)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(Color(.systemBackground))
        .cornerRadius(12)
        .shadow(radius: 2)
    }
}

struct AttestationResultView: View {
    let result: AttestationResult
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Attestierung erfolgreich!", systemImage: "checkmark.circle.fill")
                .foregroundStyle(.green)
                .font(.subheadline)
                .fontWeight(.semibold)
            
            Divider()
            
            VStack(alignment: .leading, spacing: 4) {
                Text("Key ID:")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(result.keyId)
                    .font(.system(.caption2, design: .monospaced))
                    .textSelection(.enabled)
            }
            
            Divider()
            
            VStack(alignment: .leading, spacing: 4) {
                Text("Attestierung (Base64, gekürzt):")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(result.attestationBase64.prefix(100) + "...")
                    .font(.system(.caption2, design: .monospaced))
                    .textSelection(.enabled)
                    .lineLimit(3)
            }
        }
        .padding()
        .background(Color(.systemBackground))
        .cornerRadius(8)
    }
}

struct AssertionResultView: View {
    let result: AssertionResult
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Assertion erfolgreich!", systemImage: "checkmark.circle.fill")
                .foregroundStyle(.green)
                .font(.subheadline)
                .fontWeight(.semibold)
            
            Divider()
            
            if let requestString = result.requestString {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Request-Daten:")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text(requestString)
                        .font(.system(.caption2, design: .monospaced))
                        .textSelection(.enabled)
                }
                
                Divider()
            }
            
            VStack(alignment: .leading, spacing: 4) {
                Text("Assertion (Base64, gekürzt):")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(result.assertionBase64.prefix(100) + "...")
                    .font(.system(.caption2, design: .monospaced))
                    .textSelection(.enabled)
                    .lineLimit(3)
            }
        }
        .padding()
        .background(Color(.systemBackground))
        .cornerRadius(8)
    }
}

#Preview {
    ContentView()
}
