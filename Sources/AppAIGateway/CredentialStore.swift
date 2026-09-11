import Foundation
import Security

public protocol GatewayCredentialStoring: Sendable {
    func appAttestKeyID(for appID: String) throws -> String?
    func setAppAttestKeyID(_ keyID: String?, for appID: String) throws
}

public struct KeychainGatewayCredentialStore: GatewayCredentialStoring {
    private let service: String

    public init(service: String = "dev.aigateway.credentials") {
        self.service = service
    }

    public func appAttestKeyID(for appID: String) throws -> String? {
        var query = baseQuery(appID: appID)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw KeychainError(status: status)
        }
        return String(data: data, encoding: .utf8)
    }

    public func setAppAttestKeyID(_ keyID: String?, for appID: String) throws {
        let query = baseQuery(appID: appID)
        SecItemDelete(query as CFDictionary)
        guard let keyID else { return }
        var attributes = query
        attributes[kSecValueData as String] = Data(keyID.utf8)
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else { throw KeychainError(status: status) }
    }

    private func baseQuery(appID: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "\(appID).app-attest-key",
        ]
    }
}

public struct KeychainError: Error, Sendable {
    public let status: OSStatus
}
