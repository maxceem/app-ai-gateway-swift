import CryptoKit
import Foundation

#if os(iOS)
import DeviceCheck
#endif

public protocol AppAttestProviding: Sendable {
    var isSupported: Bool { get }
    func generateKey() async throws -> String
    func attestKey(_ keyID: String, clientDataHash: Data) async throws -> Data
    func generateAssertion(_ keyID: String, clientDataHash: Data) async throws -> Data
}

public struct SystemAppAttestProvider: AppAttestProviding {
    public init() {}

    #if os(iOS)
    public var isSupported: Bool { DCAppAttestService.shared.isSupported }

    public func generateKey() async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            DCAppAttestService.shared.generateKey { keyID, error in
                if let keyID { continuation.resume(returning: keyID) }
                else { continuation.resume(throwing: error ?? URLError(.unknown)) }
            }
        }
    }

    public func attestKey(_ keyID: String, clientDataHash: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            DCAppAttestService.shared.attestKey(keyID, clientDataHash: clientDataHash) { data, error in
                if let data { continuation.resume(returning: data) }
                else { continuation.resume(throwing: error ?? URLError(.unknown)) }
            }
        }
    }

    public func generateAssertion(_ keyID: String, clientDataHash: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            DCAppAttestService.shared.generateAssertion(keyID, clientDataHash: clientDataHash) { data, error in
                if let data { continuation.resume(returning: data) }
                else { continuation.resume(throwing: error ?? URLError(.unknown)) }
            }
        }
    }
    #else
    public var isSupported: Bool { false }
    public func generateKey() async throws -> String { throw URLError(.unsupportedURL) }
    public func attestKey(_ keyID: String, clientDataHash: Data) async throws -> Data {
        _ = keyID
        _ = clientDataHash
        throw URLError(.unsupportedURL)
    }
    public func generateAssertion(_ keyID: String, clientDataHash: Data) async throws -> Data {
        _ = keyID
        _ = clientDataHash
        throw URLError(.unsupportedURL)
    }
    #endif
}

extension Data {
    var sha256: Data { Data(SHA256.hash(data: self)) }
}
