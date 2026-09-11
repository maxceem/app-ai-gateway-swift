import Foundation
import Testing
@testable import AppAIGateway

final class MockURLProtocol: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) static var handler: ((URLRequest) throws -> (HTTPURLResponse, Data))?

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        do {
            guard let handler = Self.handler else { throw URLError(.badServerResponse) }
            let (response, data) = try handler(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}

struct MockAttestProvider: AppAttestProviding {
    /// Key ids this device can no longer sign with — what a reinstall leaves
    /// behind, the Secure Enclave key having gone with the old install while
    /// the keychain entry naming it stayed.
    var deadKeyIDs: Set<String> = []

    var isSupported: Bool { true }
    func generateKey() async throws -> String { "generated-key" }
    func attestKey(_ keyID: String, clientDataHash: Data) async throws -> Data {
        Data("attestation".utf8)
    }
    func generateAssertion(_ keyID: String, clientDataHash: Data) async throws -> Data {
        // `DCError.invalidInput` is what iOS actually raises here.
        if deadKeyIDs.contains(keyID) { throw URLError(.userAuthenticationRequired) }
        return Data("assertion".utf8)
    }
}

final class MemoryCredentialStore: GatewayCredentialStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var keyID: String?

    init(keyID: String? = nil) { self.keyID = keyID }

    func appAttestKeyID(for appID: String) throws -> String? {
        lock.withLock { keyID }
    }

    func setAppAttestKeyID(_ keyID: String?, for appID: String) throws {
        lock.withLock { self.keyID = keyID }
    }
}

final class LockedCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0

    @discardableResult
    func increment() -> Int {
        lock.withLock {
            value += 1
            return value
        }
    }

    func snapshot() -> Int { lock.withLock { value } }
}

actor RefreshRecorder {
    private var values: [Bool] = []
    func record(_ value: Bool) { values.append(value) }
    func snapshot() -> [Bool] { values }
}

actor RecoveryRecorder {
    private var count = 0
    func record() { count += 1 }
    func snapshot() -> Int { count }
}

private func session() -> URLSession {
    let configuration = URLSessionConfiguration.ephemeral
    configuration.protocolClasses = [MockURLProtocol.self]
    return URLSession(configuration: configuration)
}

private func response(_ request: URLRequest, status: Int, body: String) -> (HTTPURLResponse, Data) {
    (
        HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: nil)!,
        Data(body.utf8)
    )
}

@Suite(.serialized)
struct AppAIGatewayClientTests {
    @Test
    func issuerBackedAPIKeyExchangeCachesTokenAndBuildsProxyRequest() async throws {
        let tokenCalls = LockedCounter()
        MockURLProtocol.handler = { request in
            tokenCalls.increment()
            return response(request, status: 200, body: #"{"access_token":"gateway-token","expires_in":3600}"#)
        }
        let client = AppAIGatewayClient(
            appID: "test-app",
            baseURL: URL(string: "https://gateway.test")!,
            authMode: .apiKey(
                key: "agw_test-key",
                issuerTokenProvider: { _ in "firebase-token" }
            ),
            session: session()
        )
        #expect(try await client.gatewayAccessToken() == "gateway-token")
        #expect(try await client.gatewayAccessToken() == "gateway-token")
        #expect(tokenCalls.snapshot() == 1)
        let request = try await client.authorizedRequest(provider: "openai", providerPath: "v1/responses")
        #expect(request.url?.absoluteString == "https://gateway.test/v1/apps/test-app/proxy/openai/v1/responses")
        #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer gateway-token")
        #expect(request.value(forHTTPHeaderField: "X-App-Version") != nil)
        #expect(
            AppAIGatewayClient.apiKeyTokenBody(
                issuerToken: "firebase-token",
                apiKey: "agw_test-key"
            ) == ["issuer_token": "firebase-token", "api_key": "agw_test-key"]
        )
    }

    /// Named endpoints bake the provider and model into server config, so the
    /// URL carries only the slug and the request is otherwise identical to a
    /// proxy call.
    @Test
    func endpointRequestsUseTheNamedEndpointURL() async throws {
        MockURLProtocol.handler = { request in
            response(request, status: 200, body: #"{"access_token":"gateway-token","expires_in":3600}"#)
        }
        let client = AppAIGatewayClient(
            appID: "test-app",
            baseURL: URL(string: "https://gateway.test")!,
            authMode: .apiKey(
                key: "agw_test-key",
                issuerTokenProvider: { _ in "firebase-token" }
            ),
            session: session()
        )
        #expect(
            await client.endpointURL(slug: "chat").absoluteString
                == "https://gateway.test/v1/apps/test-app/endpoints/chat"
        )
        let request = try await client.authorizedRequest(endpointSlug: "transcribe")
        #expect(request.url?.absoluteString == "https://gateway.test/v1/apps/test-app/endpoints/transcribe")
        #expect(request.httpMethod == "POST")
        #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer gateway-token")
        #expect(request.value(forHTTPHeaderField: "X-App-Version") != nil)
    }

    /// A base URL with a path prefix keeps it, and both request builders stay
    /// available while the app finishes migrating off the proxy.
    @Test
    func endpointAndProxyURLsSharePrefixHandling() async {
        let client = AppAIGatewayClient(
            appID: "calorie-tracker",
            baseURL: URL(string: "https://gateway.test/base")!,
            authMode: .apiKey(
                key: "agw_test-key",
                issuerTokenProvider: { _ in "firebase-token" }
            ),
            session: session()
        )
        #expect(
            await client.endpointURL(slug: "chat").absoluteString
                == "https://gateway.test/base/v1/apps/calorie-tracker/endpoints/chat"
        )
        #expect(
            await client.proxyURL(provider: "openai", providerPath: "v1/responses").absoluteString
                == "https://gateway.test/base/v1/apps/calorie-tracker/proxy/openai/v1/responses"
        )
        #expect(
            await client.proxyURL(provider: .openai, providerPath: "v1/responses").absoluteString
                == "https://gateway.test/base/v1/apps/calorie-tracker/proxy/openai/v1/responses"
        )
        // A second instance of a provider type is addressed by its own slug.
        #expect(
            await client.proxyURL(provider: .custom("openai-dev"), providerPath: "v1/responses")
                .absoluteString
                == "https://gateway.test/base/v1/apps/calorie-tracker/proxy/openai-dev/v1/responses"
        )
    }

    @Test
    func endpointNotFoundDecodesFromTheGatewayEnvelope() {
        #expect(GatewayErrorCode(rawValue: "endpoint_not_found") == .endpointNotFound)
    }

    /// The entitlement-sync case: the claim is missing, so the app's recovery
    /// closure runs and a refreshed token is what finally carries the claim.
    @Test
    func claimsMissingRunsRecoveryThenRetriesWithAFreshIssuerToken() async throws {
        let tokenCalls = LockedCounter()
        let refreshRecorder = RefreshRecorder()
        let recoveryRecorder = RecoveryRecorder()
        MockURLProtocol.handler = { request in
            if request.url!.path.hasSuffix("/auth/challenge") {
                return response(request, status: 200, body: #"{"challenge":"Y2hhbGxlbmdl"}"#)
            }
            if tokenCalls.increment() == 1 {
                return response(
                    request,
                    status: 403,
                    body: #"{"error":{"code":"issuer_claims_missing","message":"still syncing"}}"#
                )
            }
            return response(request, status: 200, body: #"{"access_token":"fresh-token","expires_in":3600}"#)
        }
        let client = AppAIGatewayClient(
            appID: "test-app",
            baseURL: URL(string: "https://gateway.test")!,
            authMode: .appAttest(issuerTokenProvider: { forceRefresh in
                await refreshRecorder.record(forceRefresh)
                return forceRefresh ? "issuer-fresh" : "issuer-old"
            }),
            issuerRejectionRecovery: {
                await recoveryRecorder.record()
            },
            attestProvider: MockAttestProvider(),
            credentialStore: MemoryCredentialStore(keyID: "existing-key"),
            session: session()
        )
        #expect(try await client.gatewayAccessToken() == "fresh-token")
        #expect(tokenCalls.snapshot() == 2)
        #expect(await refreshRecorder.snapshot() == [false, true])
        #expect(await recoveryRecorder.snapshot() == 1)
    }

    @Test
    func claimsMissingOnAnIssuerBackedAPIKeyRecoversTheSameWay() async throws {
        let tokenCalls = LockedCounter()
        let refreshRecorder = RefreshRecorder()
        let recoveryRecorder = RecoveryRecorder()
        MockURLProtocol.handler = { request in
            if tokenCalls.increment() == 1 {
                return response(
                    request,
                    status: 403,
                    body: #"{"error":{"code":"issuer_claims_missing","message":"still syncing"}}"#
                )
            }
            return response(request, status: 200, body: #"{"access_token":"fresh-token","expires_in":3600}"#)
        }
        let client = AppAIGatewayClient(
            appID: "test-app",
            baseURL: URL(string: "https://gateway.test")!,
            authMode: .apiKey(
                key: "agw_test-key",
                issuerTokenProvider: { forceRefresh in
                    await refreshRecorder.record(forceRefresh)
                    return forceRefresh ? "issuer-fresh" : "issuer-old"
                }
            ),
            issuerRejectionRecovery: {
                await recoveryRecorder.record()
            },
            session: session()
        )
        #expect(try await client.gatewayAccessToken() == "fresh-token")
        #expect(tokenCalls.snapshot() == 2)
        #expect(await refreshRecorder.snapshot() == [false, true])
        #expect(await recoveryRecorder.snapshot() == 1)
    }

    /// A token that did not verify is refreshed once, but must not drag the
    /// app's purchase-sync machinery in: nothing about a bad credential is an
    /// entitlement problem.
    @Test
    func rejectedIssuerTokenRetriesOnceWithoutRunningRecovery() async throws {
        let tokenCalls = LockedCounter()
        let refreshRecorder = RefreshRecorder()
        let recoveryRecorder = RecoveryRecorder()
        MockURLProtocol.handler = { request in
            if tokenCalls.increment() == 1 {
                return response(
                    request,
                    status: 403,
                    body: #"{"error":{"code":"issuer_token_rejected","message":"refresh"}}"#
                )
            }
            return response(request, status: 200, body: #"{"access_token":"fresh-token","expires_in":3600}"#)
        }
        let client = AppAIGatewayClient(
            appID: "test-app",
            baseURL: URL(string: "https://gateway.test")!,
            authMode: .apiKey(
                key: "agw_test-key",
                issuerTokenProvider: { forceRefresh in
                    await refreshRecorder.record(forceRefresh)
                    return forceRefresh ? "issuer-fresh" : "issuer-old"
                }
            ),
            issuerRejectionRecovery: {
                await recoveryRecorder.record()
            },
            session: session()
        )
        #expect(try await client.gatewayAccessToken() == "fresh-token")
        #expect(tokenCalls.snapshot() == 2)
        #expect(await refreshRecorder.snapshot() == [false, true])
        #expect(await recoveryRecorder.snapshot() == 0)
    }

    /// The gateway could not verify anything, so there is nothing to recover
    /// from and nothing a fresh token would change: one call, one error, and the
    /// caller is told it is worth trying again later.
    @Test
    func verificationUnavailableNeitherRecoversNorRefreshes() async throws {
        let tokenCalls = LockedCounter()
        let refreshRecorder = RefreshRecorder()
        let recoveryRecorder = RecoveryRecorder()
        MockURLProtocol.handler = { request in
            tokenCalls.increment()
            return response(
                request,
                status: 503,
                body: #"{"error":{"code":"issuer_verification_unavailable","message":"Issuer keys are temporarily unavailable"}}"#
            )
        }
        let client = AppAIGatewayClient(
            appID: "test-app",
            baseURL: URL(string: "https://gateway.test")!,
            authMode: .apiKey(
                key: "agw_test-key",
                issuerTokenProvider: { forceRefresh in
                    await refreshRecorder.record(forceRefresh)
                    return forceRefresh ? "issuer-fresh" : "issuer-old"
                }
            ),
            issuerRejectionRecovery: {
                await recoveryRecorder.record()
            },
            session: session()
        )

        var surfaced: GatewayError?
        do {
            _ = try await client.gatewayAccessToken()
        } catch let error as GatewayError {
            surfaced = error
        }
        #expect(surfaced?.code == .issuerVerificationUnavailable)
        #expect(surfaced?.isRetryable == true)
        #expect(tokenCalls.snapshot() == 1)
        #expect(await refreshRecorder.snapshot() == [false])
        #expect(await recoveryRecorder.snapshot() == 0)
    }

    @Test
    func newIssuerCodesDecodeFromTheGatewayEnvelope() {
        #expect(GatewayErrorCode(rawValue: "issuer_claims_missing") == .issuerClaimsMissing)
        #expect(GatewayErrorCode(rawValue: "issuer_verification_unavailable") == .issuerVerificationUnavailable)
        // A rejected token is not something waiting fixes.
        #expect(
            GatewayError(code: .issuerTokenRejected, message: "", statusCode: 403).isRetryable == false
        )
    }

    /// An outage of the gateway's billing service must not read as an unpaid
    /// customer. Both refuse the request, but only one is the customer's to fix,
    /// and an app that confuses them shows a subscriber an upsell mid-outage.
    @Test
    func billingOutageIsRetryableWhileAnUnpaidSubscriptionIsNot() throws {
        let unpaid = try #require(GatewayError(
            response: HTTPURLResponse(
                url: URL(string: "https://gateway.example.test/v1/apps/a/proxy/openai/v1/responses")!,
                statusCode: 402,
                httpVersion: nil,
                headerFields: nil
            )!,
            body: Data(#"{"error":{"code":"billing_payment_required","message":"subscribe"}}"#.utf8)
        ))
        #expect(unpaid.code == .billingPaymentRequired)
        #expect(unpaid.isRetryable == false)

        let outage = try #require(GatewayError(
            response: HTTPURLResponse(
                url: URL(string: "https://gateway.example.test/v1/apps/a/proxy/openai/v1/responses")!,
                statusCode: 503,
                httpVersion: nil,
                headerFields: ["Retry-After": "5"]
            )!,
            body: Data(#"{"error":{"code":"billing_unavailable","message":"unreachable"}}"#.utf8)
        ))
        #expect(outage.code == .billingUnavailable)
        #expect(outage.isRetryable)
        #expect(outage.monthlyRequestQuota == nil)
    }

    /// The gateway's only quota. Before it was listed, an exhausted month
    /// reached the app as `.unknown`, which says nothing an app could act on.
    @Test
    func billingRequestQuotaCodeIsRecognisedRatherThanUnknown() {
        #expect(
            GatewayErrorCode(rawValue: "billing_request_quota_exceeded")
                == .billingRequestQuotaExceeded
        )
        let error = GatewayError(
            code: .billingRequestQuotaExceeded,
            message: "exhausted",
            statusCode: 429
        )
        // Waiting is what fixes it, so it reads as retryable like any other 429.
        #expect(error.isRetryable)
    }

    /// The two quota systems, told apart at the point a client has to act.
    ///
    /// Both arrive as a 429 and both are worth waiting on, but only one is the
    /// app's own doing: an ``GatewayErrorCode/appRateLimited`` refusal is a
    /// limit the operator set and can change, and it says which scope refused.
    @Test
    func anApplicationRateLimitIsToldApartFromThePlanAllowance() throws {
        let url = URL(string: "https://gateway.test/v1/apps/a/proxy/openai/v1/responses")!
        let http = HTTPURLResponse(
            url: url,
            statusCode: 429,
            httpVersion: nil,
            headerFields: ["Retry-After": "37"]
        )!
        let error = try #require(GatewayError(
            response: http,
            body: Data(#"""
            {"error":{"code":"app_rate_limited","message":"too fast","data":{"scope":"user"}}}
            """#.utf8)
        ))

        #expect(error.code == .appRateLimited)
        #expect(error.limitScope == "user")
        #expect(error.retryAfter == 37)
        // Not the plan's allowance, so there is none of it to read.
        #expect(error.monthlyRequestQuota == nil)
        #expect(error.isRetryable)
    }

    @Test
    func anApplicationBudgetRejectionCarriesItsScopeAndRetryInstant() throws {
        let url = URL(string: "https://gateway.test/v1/apps/a/endpoints/chat")!
        let http = HTTPURLResponse(
            url: url,
            statusCode: 429,
            httpVersion: nil,
            headerFields: ["Retry-After": "86400"]
        )!
        let error = try #require(GatewayError(
            response: http,
            body: Data(#"""
            {"error":{"code":"app_budget_exhausted","message":"spent","data":{"scope":"app"}}}
            """#.utf8)
        ))

        #expect(error.code == .appBudgetExhausted)
        // An app-scoped refusal is somebody else's traffic: backing this user
        // off does not help, and a client should be able to tell.
        #expect(error.limitScope == "app")
        #expect(error.retryAfter == 86_400)
    }

    /// Only application limits carry a scope; nothing else should invent one.
    @Test
    func onlyAnApplicationLimitReportsAScope() {
        let quota = GatewayError(
            code: .billingRequestQuotaExceeded,
            message: "exhausted",
            statusCode: 429,
            data: ["scope": .string("user")]
        )
        #expect(quota.limitScope == nil)
    }

    @Test
    func aQuotaRejectionCarriesTheAllowanceTheCountAndTheResetInstant() throws {
        let body = Data(#"""
        {"error":{"code":"billing_request_quota_exceeded",
                  "message":"exhausted until 2026-10-01T00:00:00.000Z",
                  "data":{"limit":10000,"used":10000,"resetAt":"2026-10-01T00:00:00.000Z"}}}
        """#.utf8)
        let http = HTTPURLResponse(
            url: URL(string: "https://gateway.test/v1/apps/a/proxy/openai/v1/responses")!,
            statusCode: 429,
            httpVersion: nil,
            headerFields: ["Retry-After": "2419200"]
        )!

        let error = try #require(GatewayError(response: http, body: body))
        #expect(error.code == .billingRequestQuotaExceeded)
        #expect(error.statusCode == 429)
        let quota = try #require(error.monthlyRequestQuota)
        #expect(quota.limit == 10_000)
        #expect(quota.used == 10_000)
        #expect(quota.resetAt == Date(timeIntervalSince1970: 1_790_812_800))
    }

    /// A successful response is not a rejection, and a rejection that carries no
    /// `data` still reads — the accessor simply has nothing to answer with.
    @Test
    func rejectionParsingIgnoresSuccessAndToleratesAMissingDataObject() throws {
        let url = URL(string: "https://gateway.test/v1/apps/a/proxy/openai/v1/responses")!
        let success = HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!
        #expect(GatewayError(response: success, body: Data("{}".utf8)) == nil)

        let refusal = HTTPURLResponse(url: url, statusCode: 403, httpVersion: nil, headerFields: nil)!
        let error = try #require(GatewayError(
            response: refusal,
            body: Data(#"{"error":{"code":"model_not_allowed","message":"nope"}}"#.utf8)
        ))
        #expect(error.code == .modelNotAllowed)
        #expect(error.data.isEmpty)
        #expect(error.monthlyRequestQuota == nil)

        // An unparseable body still yields a rejection, just an unnamed one.
        let garbled = try #require(GatewayError(response: refusal, body: Data("not json".utf8)))
        #expect(garbled.code == .unknown)
        #expect(garbled.statusCode == 403)
    }

    /// JSON has one number type, so a count may arrive written either way.
    @Test
    func quotaCountsReadBackWhicheverWayJSONWroteThem() throws {
        let url = URL(string: "https://gateway.test/v1/apps/a/endpoints/chat")!
        let http = HTTPURLResponse(url: url, statusCode: 429, httpVersion: nil, headerFields: nil)!
        let error = try #require(GatewayError(
            response: http,
            body: Data(#"""
            {"error":{"code":"billing_request_quota_exceeded","message":"exhausted",
                      "data":{"limit":10000.0,"used":10000,"resetAt":"2026-10-01T00:00:00Z"}}}
            """#.utf8)
        ))
        let quota = try #require(error.monthlyRequestQuota)
        #expect(quota.limit == 10_000)
        // Seconds-precision instants parse too; the gateway sends milliseconds.
        #expect(quota.resetAt == Date(timeIntervalSince1970: 1_790_812_800))
    }

    /// A key the Secure Enclave has forgotten is registered afresh rather than
    /// ending the session. Signing fails on the device, before any request is
    /// made, so the gateway never gets the chance to reject it — which is why
    /// recovering from a rejection alone left a reinstalled app stuck.
    @Test
    func aKeyThisDeviceCannotSignWithIsReplaced() async throws {
        let registerCalls = LockedCounter()
        let tokenCalls = LockedCounter()
        MockURLProtocol.handler = { request in
            if request.url!.path.hasSuffix("/auth/challenge") {
                return response(request, status: 200, body: #"{"challenge":"Y2hhbGxlbmdl"}"#)
            }
            if request.url!.path.hasSuffix("/auth/register") {
                registerCalls.increment()
                return response(request, status: 200, body: #"{"user_id":"user-1"}"#)
            }
            tokenCalls.increment()
            return response(request, status: 200, body: #"{"access_token":"recovered","expires_in":3600}"#)
        }
        let store = MemoryCredentialStore(keyID: "key-from-previous-install")
        let client = AppAIGatewayClient(
            appID: "test-app",
            baseURL: URL(string: "https://gateway.test")!,
            authMode: .appAttest(issuerTokenProvider: { _ in "issuer" }),
            attestProvider: MockAttestProvider(deadKeyIDs: ["key-from-previous-install"]),
            credentialStore: store,
            session: session()
        )
        #expect(try await client.gatewayAccessToken() == "recovered")
        // Registered once, and the replacement is what gets stored.
        #expect(registerCalls.snapshot() == 1)
        #expect(tokenCalls.snapshot() == 1)
        #expect(try store.appAttestKeyID(for: "test-app") == "generated-key")
    }

    @Test
    func shortLivedTokensUseProportionalRefreshLeewayWithoutLooping() async throws {
        let tokenCalls = LockedCounter()
        MockURLProtocol.handler = { request in
            let call = tokenCalls.increment()
            return response(
                request,
                status: 200,
                body: "{\"access_token\":\"token-\(call)\",\"expires_in\":120}"
            )
        }
        let client = AppAIGatewayClient(
            appID: "test-app",
            baseURL: URL(string: "https://gateway.test")!,
            authMode: .apiKey(
                key: "agw_test-key",
                issuerTokenProvider: { _ in "firebase-token" }
            ),
            session: session()
        )
        #expect(try await client.gatewayAccessToken() == "token-1")
        #expect(try await client.gatewayAccessToken() == "token-1")
        try await Task.sleep(for: .seconds(1.2))
        #expect(tokenCalls.snapshot() == 1)
        #expect(AppAIGatewayClient.refreshDelay(for: 120) == 96)
        #expect(AppAIGatewayClient.refreshDelay(for: 3600) == 3300)
        _ = client
    }

    @Test
    func concurrentTokenRequestsShareOneExchange() async throws {
        let tokenCalls = LockedCounter()
        MockURLProtocol.handler = { request in
            tokenCalls.increment()
            return response(request, status: 200, body: #"{"access_token":"shared-token","expires_in":3600}"#)
        }
        let client = AppAIGatewayClient(
            appID: "test-app",
            baseURL: URL(string: "https://gateway.test")!,
            authMode: .apiKey(
                key: "agw_test-key",
                issuerTokenProvider: { _ in "firebase-token" }
            ),
            session: session()
        )

        async let first = client.gatewayAccessToken()
        async let second = client.gatewayAccessToken()
        #expect(try await [first, second] == ["shared-token", "shared-token"])
        #expect(tokenCalls.snapshot() == 1)
    }

    @Test
    func failedSingleFlightReleasesTheNextExchange() async throws {
        let tokenCalls = LockedCounter()
        MockURLProtocol.handler = { request in
            if tokenCalls.increment() == 1 {
                return response(
                    request,
                    status: 503,
                    body: #"{"error":{"code":"provider_error","message":"retry"}}"#
                )
            }
            return response(request, status: 200, body: #"{"access_token":"recovered","expires_in":3600}"#)
        }
        let client = AppAIGatewayClient(
            appID: "test-app",
            baseURL: URL(string: "https://gateway.test")!,
            authMode: .apiKey(
                key: "agw_test-key",
                issuerTokenProvider: { _ in "firebase-token" }
            ),
            session: session()
        )

        var firstFailed = false
        do {
            _ = try await client.gatewayAccessToken()
        } catch {
            firstFailed = true
        }
        #expect(firstFailed)
        #expect(try await client.gatewayAccessToken() == "recovered")
        #expect(tokenCalls.snapshot() == 2)
    }

    @Test
    func assertionClientDataMatchesServerCanonicalForm() {
        let value = AppAIGatewayClient.assertionClientData(app: "app", challenge: "challenge", keyID: "key")
        #expect(String(data: value, encoding: .utf8) == #"{"app":"app","challenge":"challenge","key_id":"key"}"#)
    }

    @Test
    func issuerlessAPIKeyIsAttachedDirectlyWithOptionalEndUserID() async throws {
        let networkCalls = LockedCounter()
        MockURLProtocol.handler = { request in
            networkCalls.increment()
            return response(request, status: 500, body: "{}")
        }
        let client = AppAIGatewayClient(
            appID: "machine-app",
            baseURL: URL(string: "https://gateway.test")!,
            authMode: .apiKey(key: "agw_machine-key"),
            endUserId: "customer-42",
            session: session()
        )

        #expect(try await client.gatewayAccessToken() == "agw_machine-key")
        let request = try await client.authorizedRequest(endpointSlug: "chat")
        #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer agw_machine-key")
        #expect(request.value(forHTTPHeaderField: "X-End-User-ID") == "customer-42")
        #expect(networkCalls.snapshot() == 0)
    }
}
