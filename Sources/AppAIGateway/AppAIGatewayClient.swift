import Foundation

#if canImport(UIKit)
import UIKit
#endif

public typealias IssuerTokenProvider = @Sendable (_ forceRefresh: Bool) async throws -> String
public typealias IssuerRejectionRecovery = @Sendable () async throws -> Void

/// The second path segment of a proxy URL: `/v1/apps/{app}/proxy/{slug}/…`.
///
/// A slug names one *provider instance* configured by the organization, not a
/// provider type. The first instance of each type takes its type name as the
/// default slug, which is what the well-known constants below spell; extra
/// instances carry a slug of their own, e.g. `.custom("openai-dev")`.
public struct ProviderSlug: RawRepresentable, Hashable, Sendable,
    ExpressibleByStringLiteral, CustomStringConvertible {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public init(stringLiteral value: StringLiteralType) {
        self.rawValue = value
    }

    /// Any slug the organization configured, including extra instances of a type.
    public static func custom(_ slug: String) -> ProviderSlug {
        ProviderSlug(rawValue: slug)
    }

    public static let openai: ProviderSlug = "openai"
    public static let anthropic: ProviderSlug = "anthropic"
    public static let xai: ProviderSlug = "xai"
    public static let gemini: ProviderSlug = "gemini"
    public static let perplexity: ProviderSlug = "perplexity"

    public var description: String { rawValue }
}

public enum GatewayAuthMode: Sendable {
    /// App Attest proves the client installation and the issuer token proves the user.
    case appAttest(issuerTokenProvider: IssuerTokenProvider)

    /// App Attest alone: the attested key identifies the installation, and the
    /// installation is the end user. No sign-in, and so no issuer token — match
    /// this to an application configured with the `app_install` source, which
    /// refuses a token rather than ignoring one.
    ///
    /// The key lives in the Secure Enclave for one install of one app, so it
    /// does not survive reinstalling or clearing the app's data. Per-install
    /// limits and blocks hold, but a user can shed one by starting over.
    case appAttestInstall

    /// With an issuer provider, the API key is exchanged for a per-user gateway token.
    /// Without one, the key is sent directly and is valid only for issuer-less apps.
    case apiKey(key: String, issuerTokenProvider: IssuerTokenProvider? = nil)
}

public actor AppAIGatewayClient {
    private struct AccessToken: Sendable {
        let value: String
        let refreshAt: Date
    }

    private struct TokenResponse: Decodable {
        let access_token: String
        let expires_in: TimeInterval
    }

    private struct ChallengeResponse: Decodable {
        let challenge: String
    }

    private let appID: String
    private let baseURL: URL
    private let authMode: GatewayAuthMode
    private let endUserId: String?
    private let endUserHeader: String
    private let issuerRejectionRecovery: IssuerRejectionRecovery?
    private let attestProvider: any AppAttestProviding
    private let credentialStore: any GatewayCredentialStoring
    private let session: URLSession
    private var accessToken: AccessToken?
    private var tokenExchangeTask: Task<String, Error>?
    private var refreshTask: Task<Void, Never>?

    public init(
        appID: String,
        baseURL: URL,
        authMode: GatewayAuthMode,
        endUserId: String? = nil,
        endUserHeader: String = "X-End-User-ID",
        issuerRejectionRecovery: IssuerRejectionRecovery? = nil,
        attestProvider: any AppAttestProviding = SystemAppAttestProvider(),
        credentialStore: any GatewayCredentialStoring = KeychainGatewayCredentialStore(),
        session: URLSession = .shared
    ) {
        self.appID = appID
        self.baseURL = baseURL
        self.authMode = authMode
        self.endUserId = endUserId
        self.endUserHeader = endUserHeader
        self.issuerRejectionRecovery = issuerRejectionRecovery
        self.attestProvider = attestProvider
        self.credentialStore = credentialStore
        self.session = session
    }

    deinit {
        tokenExchangeTask?.cancel()
        refreshTask?.cancel()
    }

    public func gatewayAccessToken() async throws -> String {
        if case .apiKey(let key, nil) = authMode { return key }
        if let accessToken, accessToken.refreshAt.timeIntervalSinceNow > 0 {
            return accessToken.value
        }
        return try await refreshGatewayAccessToken()
    }

    private func refreshGatewayAccessToken() async throws -> String {
        if let tokenExchangeTask { return try await tokenExchangeTask.value }
        let task = Task {
            try await self.exchangeToken(forceIssuerRefresh: false, retryIssuerOnce: true)
        }
        tokenExchangeTask = task
        defer { tokenExchangeTask = nil }
        return try await task.value
    }

    /// `provider` is a provider instance slug, not a provider type. See ``ProviderSlug``.
    public func proxyURL(provider: String, providerPath: String) -> URL {
        baseURL
            .appending(path: "v1/apps/\(appID)/proxy/\(provider)")
            .appending(path: providerPath)
    }

    public func proxyURL(provider: ProviderSlug, providerPath: String) -> URL {
        proxyURL(provider: provider.rawValue, providerPath: providerPath)
    }

    public func authorizedRequest(
        provider: String,
        providerPath: String,
        method: String = "POST"
    ) async throws -> URLRequest {
        try await authorizedRequest(
            url: proxyURL(provider: provider, providerPath: providerPath),
            method: method
        )
    }

    public func authorizedRequest(
        provider: ProviderSlug,
        providerPath: String,
        method: String = "POST"
    ) async throws -> URLRequest {
        try await authorizedRequest(
            provider: provider.rawValue,
            providerPath: providerPath,
            method: method
        )
    }

    /// A server-configured endpoint. The provider, model, and any baked
    /// parameters live in the gateway's endpoint row, so the caller sends only
    /// the request body its slug expects.
    public func endpointURL(slug: String) -> URL {
        baseURL.appending(path: "v1/apps/\(appID)/endpoints/\(slug)")
    }

    public func authorizedRequest(
        endpointSlug: String,
        method: String = "POST"
    ) async throws -> URLRequest {
        try await authorizedRequest(url: endpointURL(slug: endpointSlug), method: method)
    }

    private func authorizedRequest(url: URL, method: String) async throws -> URLRequest {
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("Bearer \(try await gatewayAccessToken())", forHTTPHeaderField: "Authorization")
        if case .apiKey(_, nil) = authMode, let endUserId {
            // Whatever the application configured. The gateway *requires* the
            // header once a header source is set, so a mismatched name here is
            // a 400 on every request rather than a silently unattributed one.
            request.setValue(endUserId, forHTTPHeaderField: endUserHeader)
        }
        request.setValue(Self.appVersion, forHTTPHeaderField: "X-App-Version")
        return request
    }

    private func exchangeToken(forceIssuerRefresh: Bool, retryIssuerOnce: Bool) async throws -> String {
        do {
            let response: TokenResponse
            switch authMode {
            case .apiKey(let key, .some(let issuerTokenProvider)):
                let issuerToken = try await issuerTokenProvider(forceIssuerRefresh)
                response = try await postJSON(
                    path: "auth/token",
                    body: Self.apiKeyTokenBody(issuerToken: issuerToken, apiKey: key)
                )
            case .apiKey(let key, nil):
                return key
            case .appAttest, .appAttestInstall:
                response = try await productionExchange(forceIssuerRefresh: forceIssuerRefresh)
            }
            let now = Date()
            let token = AccessToken(
                value: response.access_token,
                refreshAt: now.addingTimeInterval(Self.refreshDelay(for: response.expires_in))
            )
            accessToken = token
            scheduleRefresh(for: token)
            return token.value
        } catch let error as GatewayError
            where error.code == .issuerClaimsMissing && retryIssuerOnce {
            // The token verified; an entitlement claim has not landed on it yet.
            // This is the case `issuerRejectionRecovery` exists for — it is where
            // an app re-syncs a purchase — and a refreshed token is what carries
            // the claim once the sync completes.
            try await issuerRejectionRecovery?()
            return try await exchangeToken(forceIssuerRefresh: true, retryIssuerOnce: false)
        } catch let error as GatewayError
            where error.code == .issuerTokenRejected && retryIssuerOnce {
            // A token that did not verify at all. Worth one forced refresh, in
            // case the cached one had simply expired — but deliberately *not*
            // worth running the app's purchase-sync machinery, which has nothing
            // to do with an invalid credential and can cost the user a
            // store round trip for a stale token.
            return try await exchangeToken(forceIssuerRefresh: true, retryIssuerOnce: false)
        }
        // `.issuerVerificationUnavailable` is caught by neither: the gateway
        // never reached a verdict, so there is nothing to recover from and
        // nothing a fresh token would change. It surfaces to the caller as a
        // retryable error — see `GatewayError.isRetryable`.
    }

    private func productionExchange(forceIssuerRefresh: Bool) async throws -> TokenResponse {
        guard attestProvider.isSupported else {
            throw GatewayError(code: .attestFailed, message: "App Attest is unavailable on this device", statusCode: 0)
        }
        var keyID = try credentialStore.appAttestKeyID(for: appID)
        if keyID == nil {
            keyID = try await registerKey(forceIssuerRefresh: forceIssuerRefresh)
        }
        guard let keyID else {
            throw GatewayError(code: .attestFailed, message: "App Attest key registration failed", statusCode: 0)
        }
        let signed = try await signedAssertion(for: keyID, forceIssuerRefresh: forceIssuerRefresh)
        let issuerToken = try await optionalIssuerToken(forceRefresh: forceIssuerRefresh)
        do {
            return try await postJSON(path: "auth/token", body: tokenBody(issuerToken, signed))
        } catch let error as GatewayError where error.code == .attestFailed {
            // The gateway holds a key this device is no longer signing with.
            let replacement = try await replaceKey(forceIssuerRefresh: forceIssuerRefresh)
            let retry = try await sign(with: replacement)
            return try await postJSON(path: "auth/token", body: tokenBody(issuerToken, retry))
        }
    }

    private struct SignedAssertion {
        let keyID: String
        let challenge: String
        let assertion: Data
    }

    /// Signs a challenge, replacing the key first if this device can no longer
    /// sign with the one on file.
    ///
    /// The stored key id outlives the key itself. Deleting the app destroys its
    /// App Attest key in the Secure Enclave, but the keychain entry naming that
    /// key survives deletion — so the next install reads back an id it cannot
    /// sign with, and `generateAssertion` fails locally with
    /// `DCError.invalidInput` before any request leaves the device. Restoring to
    /// a new device leaves the same wreckage.
    ///
    /// Recovering from the gateway rejecting a key was never enough, because
    /// this failure happens a step earlier and never reaches the gateway at all.
    /// Treating the two the same way is what makes a reinstall something the app
    /// heals from on its next request rather than something that ends it.
    ///
    /// Only the signing call is guarded. Fetching a challenge is a network
    /// request, and a flight-mode failure there must not be mistaken for a dead
    /// key and cost the user a perfectly good one.
    private func signedAssertion(for keyID: String, forceIssuerRefresh: Bool) async throws -> SignedAssertion {
        let challengeValue = try await challenge()
        let clientData = Self.assertionClientData(app: appID, challenge: challengeValue, keyID: keyID)
        do {
            let assertion = try await attestProvider.generateAssertion(keyID, clientDataHash: clientData.sha256)
            return SignedAssertion(keyID: keyID, challenge: challengeValue, assertion: assertion)
        } catch {
            let replacement = try await replaceKey(forceIssuerRefresh: forceIssuerRefresh)
            return try await sign(with: replacement)
        }
    }

    private func sign(with keyID: String) async throws -> SignedAssertion {
        let challengeValue = try await challenge()
        let clientData = Self.assertionClientData(app: appID, challenge: challengeValue, keyID: keyID)
        let assertion = try await attestProvider.generateAssertion(keyID, clientDataHash: clientData.sha256)
        return SignedAssertion(keyID: keyID, challenge: challengeValue, assertion: assertion)
    }

    private func replaceKey(forceIssuerRefresh: Bool) async throws -> String {
        try credentialStore.setAppAttestKeyID(nil, for: appID)
        return try await registerKey(forceIssuerRefresh: forceIssuerRefresh)
    }

    /// Omits `issuer_token` entirely in install mode. The gateway refuses one
    /// there rather than ignoring it, because a client presenting a token
    /// believes it is authenticating a person.
    private func tokenBody(_ issuerToken: String?, _ signed: SignedAssertion) -> [String: String] {
        var body = [
            "key_id": signed.keyID,
            "assertion": signed.assertion.base64EncodedString(),
            "challenge": signed.challenge,
        ]
        if let issuerToken { body["issuer_token"] = issuerToken }
        return body
    }

    private func registerKey(forceIssuerRefresh: Bool) async throws -> String {
        let keyID = try await attestProvider.generateKey()
        let challenge = try await challenge()
        let challengeData = try Self.base64URLData(challenge)
        let attestation = try await attestProvider.attestKey(keyID, clientDataHash: challengeData.sha256)
        let issuerToken = try await optionalIssuerToken(forceRefresh: forceIssuerRefresh)
        struct RegisterResponse: Decodable { let user_id: String }
        var body = [
            "key_id": keyID,
            "attestation": attestation.base64EncodedString(),
            "challenge": challenge,
        ]
        if let issuerToken { body["issuer_token"] = issuerToken }
        let _: RegisterResponse = try await postJSON(path: "auth/register", body: body)
        try credentialStore.setAppAttestKeyID(keyID, for: appID)
        return keyID
    }

    private func challenge() async throws -> String {
        let response: ChallengeResponse = try await postJSON(path: "auth/challenge", body: [:])
        return response.challenge
    }

    /// The issuer token this mode presents, or `nil` where the mode has no user
    /// to prove — which is a valid state, unlike the API-key case below where a
    /// caller asked for an exchange without supplying a provider.
    private func optionalIssuerToken(forceRefresh: Bool) async throws -> String? {
        if case .appAttestInstall = authMode { return nil }
        return try await issuerToken(forceRefresh: forceRefresh)
    }

    private func issuerToken(forceRefresh: Bool) async throws -> String {
        switch authMode {
        case .appAttest(let issuerTokenProvider):
            return try await issuerTokenProvider(forceRefresh)
        case .appAttestInstall:
            throw GatewayError(
                code: .unknown,
                message: "App-install mode identifies the user by its attested key and has no issuer token",
                statusCode: 0
            )
        case .apiKey(_, .some(let issuerTokenProvider)):
            return try await issuerTokenProvider(forceRefresh)
        case .apiKey(_, nil):
            throw GatewayError(
                code: .unknown,
                message: "This API-key mode has no issuer token provider",
                statusCode: 0
            )
        }
    }

    private func postJSON<Response: Decodable>(path: String, body: [String: String]) async throws -> Response {
        var request = URLRequest(url: baseURL.appending(path: "v1/apps/\(appID)/\(path)"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else { throw URLError(.badServerResponse) }
        guard (200..<300).contains(http.statusCode) else {
            let envelope = try? JSONDecoder().decode(ErrorEnvelope.self, from: data)
            let rawCode = envelope?.error.code ?? "unknown"
            throw GatewayError(
                code: GatewayErrorCode(rawValue: rawCode) ?? .unknown,
                message: envelope?.error.message ?? "Gateway request failed",
                statusCode: http.statusCode,
                data: envelope?.error.data ?? [:],
                retryAfter: GatewayError.retryAfter(from: http)
            )
        }
        return try JSONDecoder().decode(Response.self, from: data)
    }

    private func scheduleRefresh(for token: AccessToken) {
        refreshTask?.cancel()
        let delay = max(1, token.refreshAt.timeIntervalSinceNow)
        refreshTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(delay))
            guard !Task.isCancelled else { return }
            _ = try? await self?.refreshGatewayAccessToken()
        }
    }

    static func refreshDelay(for lifetime: TimeInterval) -> TimeInterval {
        let leeway = min(300, max(15, lifetime * 0.2))
        return max(1, lifetime - leeway)
    }

    static func assertionClientData(app: String, challenge: String, keyID: String) -> Data {
        Data("{\"app\":\"\(app)\",\"challenge\":\"\(challenge)\",\"key_id\":\"\(keyID)\"}".utf8)
    }

    static func apiKeyTokenBody(issuerToken: String, apiKey: String) -> [String: String] {
        ["issuer_token": issuerToken, "api_key": apiKey]
    }

    static func base64URLData(_ value: String) throws -> Data {
        var normalized = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        normalized += String(repeating: "=", count: (4 - normalized.count % 4) % 4)
        guard let data = Data(base64Encoded: normalized) else { throw URLError(.cannotDecodeRawData) }
        return data
    }

    private static var appVersion: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0"
    }
}
