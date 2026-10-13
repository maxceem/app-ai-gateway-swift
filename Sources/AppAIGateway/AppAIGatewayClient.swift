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
        /// The App Attest key the token is bound to, in the App Attest modes:
        /// the key that signs the requests it is sent with, where any are.
        let keyID: String?
        /// Whether every request sent with this token carries an
        /// `X-AppAttest-Proof`: only when the gateway answered the exchange
        /// with `verify_on: "every_request"`.
        let signsEveryRequest: Bool
    }

    private struct TokenResponse: Decodable {
        let access_token: String
        let expires_in: TimeInterval
        /// When the gateway verifies the install's App Attest assertion:
        /// `every_request` or `token_exchange`. Absent from an older gateway,
        /// which verifies it on the exchange alone, and from API-key apps.
        let verify_on: String?
    }

    /// The `verify_on` value under which every request is signed.
    static let verifyOnEveryRequest = "every_request"

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
    private var tokenExchangeTask: Task<AccessToken, Error>?
    /// Bumped by `discardAccessToken()`. An exchange keeps the generation it
    /// started in, and its token becomes the cached one only if no discard
    /// came in between: a discarded exchange may answer an older `verify_on`.
    private var tokenGeneration = 0
    private var refreshTask: Task<Void, Never>?
    private var rateLimitHold: RateLimitHold?

    /// A refusal the gateway timed, and the instant its window closes.
    ///
    /// In memory and per client: this enforces nothing, it only stops this
    /// client from spending a window it has already been told about.
    private struct RateLimitHold {
        let until: Date
        let error: GatewayError
    }

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

    /// A token already in hand is still a token: a hold is only ever consulted
    /// where an exchange would otherwise be started, never in front of the
    /// cache, so a rate-limited window does not strand a client that is holding
    /// a perfectly good token.
    public func gatewayAccessToken() async throws -> String {
        if case .apiKey(let key, nil) = authMode { return key }
        return try await currentAccessToken().value
    }

    /// The cached token while it is fresh, a new one otherwise. Callers use the
    /// token returned rather than reading the cache afterwards: an exchange
    /// that a discard overtook returns its token without caching it.
    private func currentAccessToken() async throws -> AccessToken {
        if let accessToken, accessToken.refreshAt.timeIntervalSinceNow > 0 {
            return accessToken
        }
        return try await refreshGatewayAccessToken()
    }

    /// Refuses, without a request, while a window the gateway timed is still
    /// open, and re-raises the refusal that opened it with the time that is
    /// actually left.
    ///
    /// Without this a rate-limited window costs an Apple attestation on every
    /// call the app makes. A refused `register` leaves no key stored, so the
    /// next call finds none, generates one and attests it with Apple — against
    /// Apple's own attestation limits — only for the gateway to refuse it
    /// again, for as long as the window lasts. This is not a retry: nothing is
    /// scheduled and nothing is attempted again. It only declines to spend a
    /// window the gateway has already said is spent.
    private func heldRateLimit() throws {
        guard let hold = rateLimitHold else { return }
        let remaining = hold.until.timeIntervalSinceNow
        guard remaining > 0 else {
            rateLimitHold = nil
            return
        }
        throw GatewayError(
            code: hold.error.code,
            message: hold.error.message,
            statusCode: hold.error.statusCode,
            data: hold.error.data,
            retryAfter: remaining
        )
    }

    /// One exchange at a time per generation. Concurrent callers join the one
    /// in flight; a caller after `discardAccessToken()` starts its own, and the
    /// overtaken one finishes for those already waiting on it without becoming
    /// the cached token or scheduling a refresh.
    private func refreshGatewayAccessToken() async throws -> AccessToken {
        try heldRateLimit()
        if let tokenExchangeTask { return try await tokenExchangeTask.value }
        let generation = tokenGeneration
        let task = Task {
            let token = try await self.exchangeToken(forceIssuerRefresh: false, retryIssuerOnce: true)
            if self.tokenGeneration == generation {
                self.accessToken = token
                self.scheduleRefresh(for: token)
            }
            return token
        }
        tokenExchangeTask = task
        defer {
            // A discard has already cleared it, and may have started another.
            if tokenGeneration == generation { tokenExchangeTask = nil }
        }
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

    /// A request to a provider through the gateway, ready to send.
    ///
    /// The returned request carries `body` and, when given, `contentType`.
    /// When the app verifies App Attest on every request — the gateway says
    /// so in its token response, as `verify_on: "every_request"` — it also
    /// carries `X-AppAttest-Proof`: an assertion the device's App Attest key
    /// signed over exactly this method, URL, body and token. Send it as it is.
    /// Changing the body or the URL afterwards invalidates the proof, and the
    /// gateway refuses the request with `attest_failed`; headers other than
    /// `Authorization` may be added freely. Each proof is good for one
    /// request: build a new one per send. When the app verifies App Attest on
    /// the token exchange instead, the request carries the token alone.
    public func authorizedRequest(
        provider: String,
        providerPath: String,
        method: String = "POST",
        body: Data? = nil,
        contentType: String? = nil
    ) async throws -> URLRequest {
        try await authorizedRequest(
            url: proxyURL(provider: provider, providerPath: providerPath),
            method: method,
            body: body,
            contentType: contentType
        )
    }

    /// A request to a provider through the gateway, signed over its body and
    /// URL where the app verifies App Attest on every request: pass the body
    /// here, and change neither afterwards. See the `provider: String` form.
    public func authorizedRequest(
        provider: ProviderSlug,
        providerPath: String,
        method: String = "POST",
        body: Data? = nil,
        contentType: String? = nil
    ) async throws -> URLRequest {
        try await authorizedRequest(
            provider: provider.rawValue,
            providerPath: providerPath,
            method: method,
            body: body,
            contentType: contentType
        )
    }

    /// A server-configured endpoint. The provider, model, and any baked
    /// parameters live in the gateway's endpoint row, so the caller sends only
    /// the request body its slug expects.
    public func endpointURL(slug: String) -> URL {
        baseURL.appending(path: "v1/apps/\(appID)/endpoints/\(slug)")
    }

    /// A request to a custom endpoint, ready to send. Signed over its body and
    /// URL exactly as the provider form is, where the app verifies App Attest
    /// on every request: pass the body here, and change neither afterwards.
    public func authorizedRequest(
        endpointSlug: String,
        method: String = "POST",
        body: Data? = nil,
        contentType: String? = nil
    ) async throws -> URLRequest {
        try await authorizedRequest(
            url: endpointURL(slug: endpointSlug),
            method: method,
            body: body,
            contentType: contentType
        )
    }

    /// The gateway's own `/me` route for this app: where the calling install
    /// or user stands against the limits the app sets.
    public func currentUserURL() -> URL {
        baseURL.appending(path: "v1/apps/\(appID)/me")
    }

    /// A `GET /v1/apps/{app}/me` request, ready to send: the limits that apply
    /// to the caller, its requests today, the month's spend against its
    /// budget, and whether it is blocked. Signed like every other gateway
    /// request where the app verifies App Attest on every request, with the
    /// same key recovery, so build it here rather than from a URL of your own:
    /// there a request without a proof is refused with `401 assertion_required`, and
    /// a signed request whose URL was changed afterwards with
    /// `403 attest_failed`.
    public func currentUserRequest() async throws -> URLRequest {
        try await authorizedRequest(url: currentUserURL(), method: "GET", body: nil, contentType: nil)
    }

    /// Builds a request to a provider through the gateway, hands it to `send`,
    /// and builds it once more if the gateway answers `401`.
    ///
    /// The recommended way to send a gateway request. The client never
    /// performs the request: `send` does, with any session, configuration or
    /// networking library. Both of these fit it:
    ///
    /// ```swift
    /// { try await URLSession.shared.data(for: $0) }
    /// { try await URLSession.shared.bytes(for: $0) }
    /// ```
    ///
    /// `bytes(for:)` makes streaming work: it returns as soon as the response
    /// headers arrive, before the body, so the status is known while the
    /// stream is still unread.
    ///
    /// It recovers from the gateway's two `401`s: `auth_required` for an
    /// expired gateway token or one that names no install, and
    /// `assertion_required` for an unsigned request on an app switched to
    /// verify every request after the token was cached. On a `401` the client
    /// discards the token, builds the request again — a fresh exchange, which
    /// picks up the app's current `verify_on`, and a fresh proof, since a
    /// signed request is good for one send — and calls `send` a second time.
    /// Whatever that returns is returned, `401` included: a second refusal is
    /// real. Any `401` counts, its body unread, so one a provider returned
    /// through the proxy is retried once too.
    ///
    /// Nothing else is retried. An error `send` throws is rethrown, and every
    /// other status, `403` and `429` included, is returned as it is: a `403
    /// attest_failed` shares its status with refusals a retry cannot help, and
    /// the body, which may be a stream, is yours to read. Read a refusal with
    /// ``GatewayError/init(response:body:)``.
    ///
    /// `provider` is a provider instance slug, not a provider type. See
    /// ``ProviderSlug``. The request is built, and signed over its body and
    /// URL, exactly as `authorizedRequest` builds it: headers other than
    /// `Authorization` may be added to it inside `send`, but its body and URL
    /// must stay as they are.
    public func withAuthorizedRequest<Body: Sendable>(
        provider: String,
        providerPath: String,
        method: String = "POST",
        body: Data? = nil,
        contentType: String? = nil,
        send: @Sendable (URLRequest) async throws -> (Body, URLResponse)
    ) async throws -> (Body, URLResponse) {
        try await retryingOnce(send: send) {
            try await self.authorizedRequest(
                provider: provider,
                providerPath: providerPath,
                method: method,
                body: body,
                contentType: contentType
            )
        }
    }

    /// Sends a request to a provider through the gateway, rebuilt and sent
    /// once more on a `401`. See the `provider: String` form.
    public func withAuthorizedRequest<Body: Sendable>(
        provider: ProviderSlug,
        providerPath: String,
        method: String = "POST",
        body: Data? = nil,
        contentType: String? = nil,
        send: @Sendable (URLRequest) async throws -> (Body, URLResponse)
    ) async throws -> (Body, URLResponse) {
        try await withAuthorizedRequest(
            provider: provider.rawValue,
            providerPath: providerPath,
            method: method,
            body: body,
            contentType: contentType,
            send: send
        )
    }

    /// Sends a request to a custom endpoint, rebuilt and sent once more on a
    /// `401`. See the `provider: String` form.
    public func withAuthorizedRequest<Body: Sendable>(
        endpointSlug: String,
        method: String = "POST",
        body: Data? = nil,
        contentType: String? = nil,
        send: @Sendable (URLRequest) async throws -> (Body, URLResponse)
    ) async throws -> (Body, URLResponse) {
        try await retryingOnce(send: send) {
            try await self.authorizedRequest(
                endpointSlug: endpointSlug,
                method: method,
                body: body,
                contentType: contentType
            )
        }
    }

    /// Sends ``currentUserRequest()``, rebuilt and sent once more on a `401`.
    /// See the `provider: String` form of `withAuthorizedRequest`.
    public func withCurrentUserRequest<Body: Sendable>(
        send: @Sendable (URLRequest) async throws -> (Body, URLResponse)
    ) async throws -> (Body, URLResponse) {
        try await retryingOnce(send: send) {
            try await self.currentUserRequest()
        }
    }

    /// The one retry every `with…Request` form shares: on a `401`, discard the
    /// token and send a request built afresh, never the one already sent.
    /// Any `401` counts, the body unread, so one a provider returned through
    /// the proxy — a provider key the provider rejected, say — is retried too,
    /// at the cost of one extra token exchange and one repeated provider call.
    private func retryingOnce<Body: Sendable>(
        send: @Sendable (URLRequest) async throws -> (Body, URLResponse),
        build: () async throws -> URLRequest
    ) async throws -> (Body, URLResponse) {
        let first = try await send(try await build())
        guard let http = first.1 as? HTTPURLResponse, http.statusCode == 401 else {
            return first
        }
        discardAccessToken()
        return try await send(try await build())
    }

    /// Forgets the gateway token this client holds, so the next request runs
    /// the exchange again. For an app that sent a request itself and was
    /// refused with `auth_required`, `attest_failed` or `assertion_required`:
    /// a fresh exchange re-registers the App Attest key if the gateway no
    /// longer knows it, and picks up the app's current `verify_on`, so a
    /// request rebuilt after an app was switched to verify every request is
    /// signed. Rebuild the request once; a second refusal is real.
    /// `withAuthorizedRequest` and `withCurrentUserRequest` do this on a `401`.
    ///
    /// An exchange already in flight is not joined afterwards: the next request
    /// starts a new one, so it cannot pick up a `verify_on` answered before the
    /// discard. The one in flight is left to finish for whoever already awaits
    /// it, and its token is never cached.
    public func discardAccessToken() {
        accessToken = nil
        tokenGeneration += 1
        tokenExchangeTask = nil
        refreshTask?.cancel()
        refreshTask = nil
    }

    /// Whether this client exchanges an App Attest assertion for its token,
    /// and so may have to sign the requests it sends with it.
    private var usesAppAttest: Bool {
        switch authMode {
        case .appAttest, .appAttestInstall: return true
        case .apiKey: return false
        }
    }

    private func authorizedRequest(
        url: URL,
        method: String,
        body: Data?,
        contentType: String?
    ) async throws -> URLRequest {
        // Sent exactly as the gateway's URL parser will read it, so the path
        // and query this client signs are the ones the gateway rebuilds.
        var request = URLRequest(url: Self.whatwgNormalized(url))
        request.httpMethod = method
        request.httpBody = body
        if let contentType { request.setValue(contentType, forHTTPHeaderField: "Content-Type") }
        if case .apiKey(_, nil) = authMode, let endUserId {
            // Whatever the application configured. The gateway *requires* the
            // header once a header source is set, so a mismatched name here is
            // a 400 on every request rather than a silently unattributed one.
            request.setValue(endUserId, forHTTPHeaderField: endUserHeader)
        }
        request.setValue(Self.appVersion, forHTTPHeaderField: "X-App-Version")
        guard usesAppAttest else {
            request.setValue("Bearer \(try await gatewayAccessToken())", forHTTPHeaderField: "Authorization")
            return request
        }
        let token = try await currentAccessToken()
        // The app verifies App Attest on the token exchange, or the gateway is
        // older than `verify_on`: the assertion was checked when the token was
        // minted, and the token alone is the request's credential.
        guard token.signsEveryRequest else {
            request.setValue("Bearer \(token.value)", forHTTPHeaderField: "Authorization")
            return request
        }
        do {
            return try await signed(request, with: token)
        } catch is LocalSigningFailure {
            // The key the token is bound to cannot sign on this device any more —
            // the app was reinstalled or restored, and its Secure Enclave key
            // went with the old install. Register a replacement, exchange it for
            // a token bound to it, and sign once more; a second failure is real.
            _ = try await replaceKey(forceIssuerRefresh: false)
            discardAccessToken()
            let replacement = try await refreshGatewayAccessToken()
            // The replacement's answer decides, should the app have changed
            // its setting in between.
            guard replacement.signsEveryRequest else {
                request.setValue("Bearer \(replacement.value)", forHTTPHeaderField: "Authorization")
                return request
            }
            do {
                return try await signed(request, with: replacement)
            } catch let failure as LocalSigningFailure {
                throw failure.underlying
            }
        }
    }

    /// `generateAssertion` failing on the device, kept apart from every other
    /// failure so only it triggers a key replacement.
    private struct LocalSigningFailure: Error {
        let underlying: any Error
    }

    /// The request with its token and its proof.
    private func signed(_ request: URLRequest, with token: AccessToken) async throws -> URLRequest {
        let stored = token.keyID == nil ? try credentialStore.appAttestKeyID(for: appID) : nil
        guard let keyID = token.keyID ?? stored else {
            throw GatewayError(code: .attestFailed, message: "No App Attest key to sign the request with", statusCode: 0)
        }
        var request = request
        request.setValue("Bearer \(token.value)", forHTTPHeaderField: "Authorization")
        let timestamp = Int(Date().timeIntervalSince1970)
        let nonce = Self.randomNonce()
        let clientData = Self.requestClientData(
            appID: appID,
            method: request.httpMethod ?? "GET",
            pathAndQuery: Self.pathAndQuery(of: request.url!),
            body: request.httpBody,
            token: token.value,
            timestamp: timestamp,
            nonce: nonce
        )
        let assertion: Data
        do {
            assertion = try await attestProvider.generateAssertion(keyID, clientDataHash: clientData.sha256)
        } catch {
            throw LocalSigningFailure(underlying: error)
        }
        request.setValue(
            Self.proofHeader(timestamp: timestamp, nonce: nonce, assertion: assertion),
            forHTTPHeaderField: "X-AppAttest-Proof"
        )
        return request
    }

    /// The first line of every signed request's client data, naming the format.
    static let requestProofDomain = "appaigateway-request-v1"

    /// What the device signs for one request: these lines joined by `\n`,
    /// with no trailing newline. The gateway rebuilds the same bytes from the
    /// request it receives; the golden test pins them on both sides.
    static func requestClientData(
        appID: String,
        method: String,
        pathAndQuery: String,
        body: Data?,
        token: String,
        timestamp: Int,
        nonce: String
    ) -> Data {
        let lines = [
            requestProofDomain,
            appID,
            method.uppercased(),
            pathAndQuery,
            (body ?? Data()).sha256.base64URLEncodedString(),
            Data(token.utf8).sha256.base64URLEncodedString(),
            String(timestamp),
            nonce,
        ]
        return Data(lines.joined(separator: "\n").utf8)
    }

    /// The URL's path and query as the gateway reads them: Foundation's
    /// percent-encoded form, normalized the way the WHATWG URL parser
    /// normalizes it. An empty query is no query.
    static func pathAndQuery(of url: URL) -> String {
        let components = URLComponents(url: url, resolvingAgainstBaseURL: true)
        let path = whatwgPath(components?.percentEncodedPath ?? url.path)
        guard let query = components?.percentEncodedQuery, !query.isEmpty else { return path }
        return "\(path)?\(whatwgQuery(query))"
    }

    /// The URL rewritten so its path and query are exactly what the WHATWG URL
    /// parser makes of them: the gateway's runtime reads every request that
    /// way, and Foundation's own encoding differs on a few bytes — `'` in a
    /// query, `^` in a path, dot segments. Returned unchanged if it cannot be
    /// rebuilt.
    static func whatwgNormalized(_ url: URL) -> URL {
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: true) else { return url }
        components.percentEncodedPath = ""
        components.percentEncodedQuery = nil
        components.fragment = nil
        guard let origin = components.string else { return url }
        return URL(string: origin + pathAndQuery(of: url)) ?? url
    }

    /// The WHATWG path percent-encode set beyond controls and non-ASCII:
    /// space, `"`, `#`, `<`, `>`, `?`, `^`, `` ` ``, `{` and `}`.
    private static let pathEncodeSet: Set<UInt8> = [0x20, 0x22, 0x23, 0x3C, 0x3E, 0x3F, 0x5E, 0x60, 0x7B, 0x7D]
    /// The WHATWG special-scheme query percent-encode set beyond controls and
    /// non-ASCII: space, `"`, `#`, `<`, `>` and `'`.
    private static let queryEncodeSet: Set<UInt8> = [0x20, 0x22, 0x23, 0x3C, 0x3E, 0x27]

    /// Percent-encodes what the WHATWG parser would, byte by byte. `%` is never
    /// encoded, so an escape already present — valid or not — is left as is.
    private static func whatwgEncode(_ value: Substring, extra: Set<UInt8>) -> String {
        var output = ""
        for byte in value.utf8 {
            if byte < 0x20 || byte > 0x7E || extra.contains(byte) {
                output += String(format: "%%%02X", byte)
            } else {
                output.unicodeScalars.append(Unicode.Scalar(byte))
            }
        }
        return output
    }

    /// A path as the WHATWG parser leaves it for an `https` URL: `\` read as
    /// `/`, `.` and `..` segments (`%2e` spelled or not) resolved, and the
    /// path percent-encode set applied to what remains.
    static func whatwgPath(_ path: String) -> String {
        var segments = path.replacingOccurrences(of: "\\", with: "/")
            .split(separator: "/", omittingEmptySubsequences: false)
        if segments.first == "" { segments.removeFirst() }
        var output: [String] = []
        for (index, segment) in segments.enumerated() {
            let lowered = segment.lowercased()
            let isLast = index == segments.count - 1
            if lowered == "." || lowered == "%2e" {
                if isLast { output.append("") }
            } else if ["..", ".%2e", "%2e.", "%2e%2e"].contains(lowered) {
                if !output.isEmpty { output.removeLast() }
                if isLast { output.append("") }
            } else {
                output.append(whatwgEncode(segment, extra: pathEncodeSet))
            }
        }
        return "/" + output.joined(separator: "/")
    }

    /// A query as the WHATWG parser leaves it for an `https` URL.
    static func whatwgQuery(_ query: String) -> String {
        whatwgEncode(query[...], extra: queryEncodeSet)
    }

    /// `v1.<timestamp>.<nonce>.<assertion>`, the value of `X-AppAttest-Proof`.
    static func proofHeader(timestamp: Int, nonce: String, assertion: Data) -> String {
        "v1.\(timestamp).\(nonce).\(assertion.base64URLEncodedString())"
    }

    /// Sixteen random bytes, base64url without padding.
    static func randomNonce() -> String {
        var generator = SystemRandomNumberGenerator()
        let bytes = (0..<16).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
        return Data(bytes).base64URLEncodedString()
    }

    /// Mints a token; `refreshGatewayAccessToken` decides whether it is cached.
    private func exchangeToken(forceIssuerRefresh: Bool, retryIssuerOnce: Bool) async throws -> AccessToken {
        do {
            let response: TokenResponse
            var keyID: String?
            switch authMode {
            case .apiKey(let key, .some(let issuerTokenProvider)):
                let issuerToken = try await issuerTokenProvider(forceIssuerRefresh)
                response = try await postJSON(
                    path: "auth/token",
                    body: Self.apiKeyTokenBody(issuerToken: issuerToken, apiKey: key)
                )
            case .apiKey(let key, nil):
                // Never reached: `gatewayAccessToken` returns the key itself.
                return AccessToken(value: key, refreshAt: .distantFuture, keyID: nil, signsEveryRequest: false)
            case .appAttest, .appAttestInstall:
                (response, keyID) = try await productionExchange(forceIssuerRefresh: forceIssuerRefresh)
            }
            let now = Date()
            let token = AccessToken(
                value: response.access_token,
                refreshAt: now.addingTimeInterval(Self.refreshDelay(for: response.expires_in)),
                keyID: keyID,
                signsEveryRequest: keyID != nil && response.verify_on == Self.verifyOnEveryRequest
            )
            return token
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

    /// The token, and the key it is bound to: the gateway mints it for the
    /// install whose key signed the exchange, and where it verifies every
    /// request, refuses each one that another key signed.
    private func productionExchange(forceIssuerRefresh: Bool) async throws -> (TokenResponse, String) {
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
            return (try await postJSON(path: "auth/token", body: tokenBody(issuerToken, signed)), signed.keyID)
        } catch let error as GatewayError where error.code == .attestFailed {
            // The gateway holds a key this device is no longer signing with.
            let replacement = try await replaceKey(forceIssuerRefresh: forceIssuerRefresh)
            let retry = try await sign(with: replacement)
            return (try await postJSON(path: "auth/token", body: tokenBody(issuerToken, retry)), retry.keyID)
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

    /// Registers a replacement, and lets `registerKey` store it once the
    /// gateway has accepted it.
    ///
    /// The old id is deliberately *not* cleared first. Clearing up front is only
    /// free when the registration that follows succeeds; when it fails — and a
    /// rate-limited one above all — it leaves nothing stored at all, and every
    /// later call then starts from no key and attests a brand-new one with
    /// Apple. Keeping the old id until a new one replaces it costs at most one
    /// refused attempt on the next call, and saves the one case where the id was
    /// never the problem: `generateAssertion` can fail for a reason that has
    /// nothing to do with the key, and a device that threw its working key away
    /// for one of those can never get it back.
    private func replaceKey(forceIssuerRefresh: Bool) async throws -> String {
        try await registerKey(forceIssuerRefresh: forceIssuerRefresh)
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
            let error = GatewayError(
                code: GatewayErrorCode(rawValue: rawCode) ?? .unknown,
                message: envelope?.error.message ?? "Gateway request failed",
                statusCode: http.statusCode,
                data: envelope?.error.data ?? [:],
                retryAfter: GatewayError.retryAfter(from: http)
            )
            // Every request this method sends is one of the three
            // authentication endpoints the gateway counts, so this is the one
            // place a timed refusal can be caught for all of them. Any `429`
            // that names a wait is honoured, whatever its code: the gateway has
            // said when to come back, and a client that calls sooner is only
            // spending the window it was asked to wait out.
            if http.statusCode == 429, let seconds = error.retryAfter, seconds > 0 {
                rateLimitHold = RateLimitHold(
                    until: Date().addingTimeInterval(seconds),
                    error: error
                )
            }
            throw error
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
