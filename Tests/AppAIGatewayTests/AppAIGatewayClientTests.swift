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
    /// Counts the attestations Apple would have been asked for. A reference so
    /// the provider can stay the value type the client takes.
    var attestations: LockedCounter?
    /// Keys that stop signing part way through a test, for a reinstall that
    /// happens after a token was already minted.
    var dying: DyingKeys?
    /// Every assertion signed, with the key and the client data hash it was over.
    var signatures: SignatureLog?

    var isSupported: Bool { true }
    func generateKey() async throws -> String { "generated-key" }
    func attestKey(_ keyID: String, clientDataHash: Data) async throws -> Data {
        attestations?.increment()
        return Data("attestation".utf8)
    }
    func generateAssertion(_ keyID: String, clientDataHash: Data) async throws -> Data {
        // `DCError.invalidInput` is what iOS actually raises here.
        if deadKeyIDs.contains(keyID) || dying?.isDead(keyID) == true {
            throw URLError(.userAuthenticationRequired)
        }
        signatures?.record(keyID: keyID, hash: clientDataHash)
        return Data("assertion".utf8)
    }
}

final class DyingKeys: @unchecked Sendable {
    private let lock = NSLock()
    private var dead: Set<String> = []
    func kill(_ keyID: String) { lock.withLock { _ = dead.insert(keyID) } }
    func isDead(_ keyID: String) -> Bool { lock.withLock { dead.contains(keyID) } }
}

final class SignatureLog: @unchecked Sendable {
    private let lock = NSLock()
    private var entries: [(keyID: String, hash: Data)] = []
    func record(keyID: String, hash: Data) { lock.withLock { entries.append((keyID, hash)) } }
    func snapshot() -> [(keyID: String, hash: Data)] { lock.withLock { entries } }
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

    @Test
    func expiredAccountLifecycleErrorsRequireOwnerAction() throws {
        for (wireCode, expected) in [
            ("unclaimed_access_expired", GatewayErrorCode.unclaimedAccessExpired),
            ("account_expired", GatewayErrorCode.accountExpired),
        ] {
            let error = try #require(GatewayError(
                response: HTTPURLResponse(
                    url: URL(string: "https://gateway.example.test/v1/apps/a/proxy/openai/v1/responses")!,
                    statusCode: 403, httpVersion: nil, headerFields: nil
                )!,
                body: Data("{\"error\":{\"code\":\"\(wireCode)\",\"message\":\"Account action required\"}}".utf8)
            ))
            #expect(error.code == expected)
            #expect(error.isRetryable == false)
            #expect(error.monthlyRequestQuota == nil)
        }
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

    /// The gateway's own protection of its authentication endpoints is not one
    /// of the limits an application sets on its users, so it carries no scope
    /// to read — but it is still something waiting fixes.
    @Test
    func theGatewaysOwnAuthenticationLimitIsReadAndCarriesNoScope() throws {
        #expect(GatewayErrorCode(rawValue: "rate_limited") == .rateLimited)
        let url = URL(string: "https://gateway.test/v1/apps/a/auth/token")!
        let http = HTTPURLResponse(
            url: url,
            statusCode: 429,
            httpVersion: nil,
            headerFields: ["Retry-After": "45"]
        )!
        let error = try #require(GatewayError(
            response: http,
            body: Data(#"""
            {"error":{"code":"rate_limited","message":"too many",
                      "data":{"scope":"app_auth_token"}}}
            """#.utf8)
        ))

        #expect(error.code == .rateLimited)
        #expect(error.retryAfter == 45)
        #expect(error.isRetryable)
        // `scope` names the endpoint here, not a limit the application set, so
        // `limitScope` must not answer with it.
        #expect(error.limitScope == nil)
        #expect(error.monthlyRequestQuota == nil)
    }

    /// A refused registration must not cost an Apple attestation per call.
    ///
    /// Registering is where this bites hardest: the gateway refuses before a key
    /// is stored, so without a hold the next call finds no key, generates one
    /// and attests it with Apple all over again.
    @Test
    func aRateLimitedRegistrationIsWaitedOutWithoutAnotherAttestation() async throws {
        let attestations = LockedCounter()
        let requests = LockedCounter()
        MockURLProtocol.handler = { request in
            requests.increment()
            if request.url!.path.hasSuffix("/auth/challenge") {
                return response(request, status: 200, body: #"{"challenge":"Y2hhbGxlbmdl"}"#)
            }
            return (
                HTTPURLResponse(
                    url: request.url!,
                    statusCode: 429,
                    httpVersion: nil,
                    headerFields: ["Retry-After": "1"]
                )!,
                Data(#"""
                {"error":{"code":"rate_limited","message":"too many",
                          "data":{"scope":"app_auth_register"}}}
                """#.utf8)
            )
        }
        let store = MemoryCredentialStore()
        let client = AppAIGatewayClient(
            appID: "test-app",
            baseURL: URL(string: "https://gateway.test")!,
            authMode: .appAttest(issuerTokenProvider: { _ in "issuer" }),
            attestProvider: MockAttestProvider(attestations: attestations),
            credentialStore: store,
            session: session()
        )

        var first: GatewayError?
        do {
            _ = try await client.gatewayAccessToken()
        } catch let error as GatewayError {
            first = error
        }
        #expect(first?.code == .rateLimited)
        #expect(first?.retryAfter == 1)
        let spent = requests.snapshot()
        #expect(attestations.snapshot() == 1)
        // Nothing was stored, which is exactly the state that would otherwise
        // send the next call back to Apple for another key.
        #expect(try store.appAttestKeyID(for: "test-app") == nil)

        var second: GatewayError?
        do {
            _ = try await client.gatewayAccessToken()
        } catch let error as GatewayError {
            second = error
        }
        #expect(second?.code == .rateLimited)
        // Re-raised with what is left of the window rather than what it began as.
        #expect((second?.retryAfter ?? 0) > 0)
        #expect((second?.retryAfter ?? .infinity) <= 1)
        // The whole point: no second attestation, and no second request.
        #expect(attestations.snapshot() == 1)
        #expect(requests.snapshot() == spent)

        // Once the window closes the client goes back to the gateway by itself.
        try await Task.sleep(for: .milliseconds(1_200))
        _ = try? await client.gatewayAccessToken()
        #expect(requests.snapshot() > spent)
    }

    /// A refused token exchange is not a rejected key, so nothing about the key
    /// may change: no registration, no attestation, and the stored id stays.
    @Test
    func aRateLimitedTokenExchangeDoesNotReRegisterTheKey() async throws {
        let registerCalls = LockedCounter()
        let attestations = LockedCounter()
        let requests = LockedCounter()
        MockURLProtocol.handler = { request in
            requests.increment()
            if request.url!.path.hasSuffix("/auth/challenge") {
                return response(request, status: 200, body: #"{"challenge":"Y2hhbGxlbmdl"}"#)
            }
            if request.url!.path.hasSuffix("/auth/register") {
                registerCalls.increment()
                return response(request, status: 200, body: #"{"user_id":"user-1"}"#)
            }
            return (
                HTTPURLResponse(
                    url: request.url!,
                    statusCode: 429,
                    httpVersion: nil,
                    headerFields: ["Retry-After": "30"]
                )!,
                Data(#"""
                {"error":{"code":"rate_limited","message":"too many",
                          "data":{"scope":"app_auth_token"}}}
                """#.utf8)
            )
        }
        let store = MemoryCredentialStore(keyID: "key-in-good-standing")
        let client = AppAIGatewayClient(
            appID: "test-app",
            baseURL: URL(string: "https://gateway.test")!,
            authMode: .appAttest(issuerTokenProvider: { _ in "issuer" }),
            attestProvider: MockAttestProvider(attestations: attestations),
            credentialStore: store,
            session: session()
        )

        var surfaced: GatewayError?
        do {
            _ = try await client.gatewayAccessToken()
        } catch let error as GatewayError {
            surfaced = error
        }
        #expect(surfaced?.code == .rateLimited)
        #expect(surfaced?.retryAfter == 30)
        #expect(registerCalls.snapshot() == 0)
        #expect(attestations.snapshot() == 0)
        #expect(try store.appAttestKeyID(for: "test-app") == "key-in-good-standing")

        let spent = requests.snapshot()
        _ = try? await client.gatewayAccessToken()
        #expect(requests.snapshot() == spent)
        #expect(registerCalls.snapshot() == 0)
    }

    // MARK: Per-request App Attest proofs

    /// The exact bytes the gateway rebuilds for one request; its own golden
    /// test in `test/request-proof.test.ts` pins the same string.
    @Test
    func requestClientDataMatchesTheGatewayByteForByte() {
        let data = AppAIGatewayClient.requestClientData(
            appID: "my-app",
            method: "post",
            pathAndQuery: "/v1/apps/my-app/proxy/openai/v1/responses?x=1",
            body: Data(#"{"model":"gpt-5.6-sol"}"#.utf8),
            token: "token-value",
            timestamp: 1_767_225_600,
            nonce: "AAAAAAAAAAAAAAAAAAAAAA"
        )
        #expect(String(data: data, encoding: .utf8) == [
            "appaigateway-request-v1",
            "my-app",
            "POST",
            "/v1/apps/my-app/proxy/openai/v1/responses?x=1",
            "-PUEzjp5RIbD6WFR4AYaosj8uORXKjdf9GqkXTE8ZjY",
            "5sAqV0LqnU3liOubnee-1D3BcBFVIYa-0-mLLFlY_0o",
            "1767225600",
            "AAAAAAAAAAAAAAAAAAAAAA",
        ].joined(separator: "\n"))
    }

    @Test
    func anAbsentOrEmptyBodyHashesAsTheEmptyString() {
        let emptyHash = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
        for body in [nil, Data()] as [Data?] {
            let data = AppAIGatewayClient.requestClientData(
                appID: "a", method: "GET", pathAndQuery: "/", body: body,
                token: "t", timestamp: 1, nonce: "AAAAAAAAAAAAAAAAAAAAAA"
            )
            let lines = String(data: data, encoding: .utf8)!.split(separator: "\n", omittingEmptySubsequences: false)
            #expect(lines[4] == Substring(emptyHash))
        }
    }

    @Test
    func pathAndQueryAreReadAsSent() {
        #expect(
            AppAIGatewayClient.pathAndQuery(of: URL(string: "https://g.test/v1/apps/a/proxy/openai/v1/responses?x=1&y=%20")!)
                == "/v1/apps/a/proxy/openai/v1/responses?x=1&y=%20"
        )
        #expect(AppAIGatewayClient.pathAndQuery(of: URL(string: "https://g.test/v1/apps/a/me?")!) == "/v1/apps/a/me")
    }

    @Test
    func appAttestRequestsCarryAWellFormedProofOverTheirBody() async throws {
        let signatures = SignatureLog()
        MockURLProtocol.handler = { request in
            if request.url!.path.hasSuffix("/auth/challenge") {
                return response(request, status: 200, body: #"{"challenge":"Y2hhbGxlbmdl"}"#)
            }
            return response(request, status: 200, body: #"{"access_token":"gateway-token","expires_in":3600,"verify_on":"every_request"}"#)
        }
        let client = AppAIGatewayClient(
            appID: "test-app",
            baseURL: URL(string: "https://gateway.test")!,
            authMode: .appAttestInstall,
            attestProvider: MockAttestProvider(signatures: signatures),
            credentialStore: MemoryCredentialStore(keyID: "existing-key"),
            session: session()
        )
        let body = Data(#"{"model":"gpt-5.6-sol","input":"hi"}"#.utf8)
        let request = try await client.authorizedRequest(
            provider: .openai,
            providerPath: "v1/responses",
            body: body,
            contentType: "application/json"
        )
        #expect(request.httpBody == body)
        #expect(request.value(forHTTPHeaderField: "Content-Type") == "application/json")
        #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer gateway-token")
        let proof = try #require(request.value(forHTTPHeaderField: "X-AppAttest-Proof"))
        let parts = proof.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        #expect(parts.count == 4)
        #expect(parts[0] == "v1")
        let timestamp = try #require(Int(parts[1]))
        #expect(abs(Double(timestamp) - Date().timeIntervalSince1970) < 60)
        #expect(parts[2].count == 22)
        #expect(parts[2].allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" })
        #expect(parts[3] == Data("assertion".utf8).base64URLEncodedString())

        // The last signature is the request's, over exactly what was sent.
        let signed = try #require(signatures.snapshot().last)
        #expect(signed.keyID == "existing-key")
        let expected = AppAIGatewayClient.requestClientData(
            appID: "test-app",
            method: "POST",
            pathAndQuery: "/v1/apps/test-app/proxy/openai/v1/responses",
            body: body,
            token: "gateway-token",
            timestamp: timestamp,
            nonce: parts[2]
        ).sha256
        #expect(signed.hash == expected)

        // Each request is signed afresh: a proof is good for one send.
        let second = try await client.authorizedRequest(endpointSlug: "chat", body: body)
        #expect(second.value(forHTTPHeaderField: "X-AppAttest-Proof") != proof)
    }

    /// An app that verifies App Attest on the token exchange, and an older
    /// gateway that says nothing about it: the token alone, nothing signed.
    @Test
    func requestsCarryOnlyTheTokenUnlessTheGatewayVerifiesEveryRequest() async throws {
        for tokenBody in [
            #"{"access_token":"gateway-token","expires_in":3600,"verify_on":"token_exchange"}"#,
            #"{"access_token":"gateway-token","expires_in":3600}"#,
        ] {
            let signatures = SignatureLog()
            MockURLProtocol.handler = { request in
                if request.url!.path.hasSuffix("/auth/challenge") {
                    return response(request, status: 200, body: #"{"challenge":"Y2hhbGxlbmdl"}"#)
                }
                return response(request, status: 200, body: tokenBody)
            }
            let client = AppAIGatewayClient(
                appID: "test-app",
                baseURL: URL(string: "https://gateway.test")!,
                authMode: .appAttestInstall,
                attestProvider: MockAttestProvider(signatures: signatures),
                credentialStore: MemoryCredentialStore(keyID: "existing-key"),
                session: session()
            )
            let body = Data("{}".utf8)
            let request = try await client.authorizedRequest(provider: .openai, providerPath: "v1/responses", body: body)
            #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer gateway-token")
            #expect(request.value(forHTTPHeaderField: "X-AppAttest-Proof") == nil)
            #expect(request.httpBody == body)
            let me = try await client.currentUserRequest()
            #expect(me.value(forHTTPHeaderField: "Authorization") == "Bearer gateway-token")
            #expect(me.value(forHTTPHeaderField: "X-AppAttest-Proof") == nil)
            // The exchange's own assertion is the only one the key signed.
            #expect(signatures.snapshot().count == 1)
        }
    }

    /// The app is switched to verify every request while this client holds a
    /// token issued under token_exchange: its requests go unsigned and are
    /// refused with `assertion_required`, until the app discards the token and
    /// rebuilds the request, which re-exchanges and signs.
    @Test
    func aDiscardedTokenPicksUpASwitchToEveryRequest() async throws {
        let signatures = SignatureLog()
        let tokens = LockedCounter()
        MockURLProtocol.handler = { request in
            if request.url!.path.hasSuffix("/auth/challenge") {
                return response(request, status: 200, body: #"{"challenge":"Y2hhbGxlbmdl"}"#)
            }
            let issued = tokens.increment()
            let verifyOn = issued == 1 ? "token_exchange" : "every_request"
            return response(
                request,
                status: 200,
                body: "{\"access_token\":\"token-\(issued)\",\"expires_in\":3600,\"verify_on\":\"\(verifyOn)\"}"
            )
        }
        let client = AppAIGatewayClient(
            appID: "test-app",
            baseURL: URL(string: "https://gateway.test")!,
            authMode: .appAttestInstall,
            attestProvider: MockAttestProvider(signatures: signatures),
            credentialStore: MemoryCredentialStore(keyID: "existing-key"),
            session: session()
        )
        let body = Data("{}".utf8)
        let unsigned = try await client.authorizedRequest(provider: .openai, providerPath: "v1/responses", body: body)
        #expect(unsigned.value(forHTTPHeaderField: "Authorization") == "Bearer token-1")
        #expect(unsigned.value(forHTTPHeaderField: "X-AppAttest-Proof") == nil)
        // Still cached: nothing changes until the app discards the token.
        let stillUnsigned = try await client.authorizedRequest(provider: .openai, providerPath: "v1/responses", body: body)
        #expect(stillUnsigned.value(forHTTPHeaderField: "X-AppAttest-Proof") == nil)
        #expect(tokens.snapshot() == 1)

        // The gateway refused it with assertion_required; the app recovers.
        await client.discardAccessToken()
        let signed = try await client.authorizedRequest(provider: .openai, providerPath: "v1/responses", body: body)
        #expect(tokens.snapshot() == 2)
        #expect(signed.value(forHTTPHeaderField: "Authorization") == "Bearer token-2")
        #expect(signed.value(forHTTPHeaderField: "X-AppAttest-Proof") != nil)
        #expect(signatures.snapshot().last?.keyID == "existing-key")
    }

    @Test
    func apiKeyModesSendNoProof() async throws {
        MockURLProtocol.handler = { request in
            response(request, status: 200, body: #"{"access_token":"gateway-token","expires_in":3600,"verify_on":"every_request"}"#)
        }
        for mode in [
            GatewayAuthMode.apiKey(key: "agw_machine-key"),
            GatewayAuthMode.apiKey(key: "agw_test-key", issuerTokenProvider: { _ in "issuer" }),
        ] {
            let client = AppAIGatewayClient(
                appID: "test-app",
                baseURL: URL(string: "https://gateway.test")!,
                authMode: mode,
                session: session()
            )
            let request = try await client.authorizedRequest(
                provider: .openai, providerPath: "v1/responses", body: Data("{}".utf8)
            )
            #expect(request.value(forHTTPHeaderField: "X-AppAttest-Proof") == nil)
            #expect(request.httpBody == Data("{}".utf8))
        }
    }

    /// A reinstall after the token was minted: the key the token is bound to
    /// can no longer sign, so the client registers a replacement, exchanges it
    /// for a token bound to the new key, and signs the request once more.
    @Test
    func aKeyThatStopsSigningIsReplacedAndTheRequestSignedOnceMore() async throws {
        let dying = DyingKeys()
        let signatures = SignatureLog()
        let registers = LockedCounter()
        let tokens = LockedCounter()
        MockURLProtocol.handler = { request in
            if request.url!.path.hasSuffix("/auth/challenge") {
                return response(request, status: 200, body: #"{"challenge":"Y2hhbGxlbmdl"}"#)
            }
            if request.url!.path.hasSuffix("/auth/register") {
                registers.increment()
                return response(request, status: 200, body: #"{"user_id":"generated-key"}"#)
            }
            let issued = tokens.increment()
            return response(request, status: 200, body: "{\"access_token\":\"token-\(issued)\",\"expires_in\":3600,\"verify_on\":\"every_request\"}")
        }
        let store = MemoryCredentialStore(keyID: "existing-key")
        let client = AppAIGatewayClient(
            appID: "test-app",
            baseURL: URL(string: "https://gateway.test")!,
            authMode: .appAttestInstall,
            attestProvider: MockAttestProvider(dying: dying, signatures: signatures),
            credentialStore: store,
            session: session()
        )
        #expect(try await client.gatewayAccessToken() == "token-1")
        dying.kill("existing-key")

        let request = try await client.authorizedRequest(provider: .openai, providerPath: "v1/responses", body: Data("{}".utf8))
        #expect(registers.snapshot() == 1)
        #expect(try store.appAttestKeyID(for: "test-app") == "generated-key")
        // Bound to the new key: a token for the old one would be refused.
        #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer token-2")
        #expect(request.value(forHTTPHeaderField: "X-AppAttest-Proof") != nil)
        #expect(signatures.snapshot().last?.keyID == "generated-key")
    }

    @Test
    func theNewCodesDecode() {
        #expect(GatewayErrorCode(rawValue: "assertion_required") == .assertionRequired)
        let error = GatewayError(
            code: .appRateLimited, message: "", statusCode: 429, data: ["scope": .string("install")]
        )
        #expect(error.limitScope == "install")
    }

    /// `/me` is a gateway request like any other: signed in the App Attest
    /// modes, over a `GET` with no body, by the key the token is bound to.
    @Test
    func currentUserRequestIsASignedGetOfMe() async throws {
        let signatures = SignatureLog()
        MockURLProtocol.handler = { request in
            if request.url!.path.hasSuffix("/auth/challenge") {
                return response(request, status: 200, body: #"{"challenge":"Y2hhbGxlbmdl"}"#)
            }
            return response(request, status: 200, body: #"{"access_token":"gateway-token","expires_in":3600,"verify_on":"every_request"}"#)
        }
        let client = AppAIGatewayClient(
            appID: "test-app",
            baseURL: URL(string: "https://gateway.test/base")!,
            authMode: .appAttestInstall,
            attestProvider: MockAttestProvider(signatures: signatures),
            credentialStore: MemoryCredentialStore(keyID: "existing-key"),
            session: session()
        )
        #expect(await client.currentUserURL().absoluteString == "https://gateway.test/base/v1/apps/test-app/me")
        let request = try await client.currentUserRequest()
        #expect(request.httpMethod == "GET")
        #expect(request.httpBody == nil)
        #expect(request.url?.absoluteString == "https://gateway.test/base/v1/apps/test-app/me")
        #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer gateway-token")
        let proof = try #require(request.value(forHTTPHeaderField: "X-AppAttest-Proof"))
        let parts = proof.split(separator: ".").map(String.init)
        let expected = AppAIGatewayClient.requestClientData(
            appID: "test-app",
            method: "GET",
            pathAndQuery: "/base/v1/apps/test-app/me",
            body: nil,
            token: "gateway-token",
            timestamp: try #require(Int(parts[1])),
            nonce: parts[2]
        ).sha256
        let signed = try #require(signatures.snapshot().last)
        #expect(signed.keyID == "existing-key")
        #expect(signed.hash == expected)
    }

    @Test
    func currentUserRequestRecoversADeadKeyLikeAnyOtherRequest() async throws {
        let dying = DyingKeys()
        let registers = LockedCounter()
        let tokens = LockedCounter()
        MockURLProtocol.handler = { request in
            if request.url!.path.hasSuffix("/auth/challenge") {
                return response(request, status: 200, body: #"{"challenge":"Y2hhbGxlbmdl"}"#)
            }
            if request.url!.path.hasSuffix("/auth/register") {
                registers.increment()
                return response(request, status: 200, body: #"{"user_id":"generated-key"}"#)
            }
            let issued = tokens.increment()
            return response(request, status: 200, body: "{\"access_token\":\"token-\(issued)\",\"expires_in\":3600,\"verify_on\":\"every_request\"}")
        }
        let client = AppAIGatewayClient(
            appID: "test-app",
            baseURL: URL(string: "https://gateway.test")!,
            authMode: .appAttestInstall,
            attestProvider: MockAttestProvider(dying: dying),
            credentialStore: MemoryCredentialStore(keyID: "existing-key"),
            session: session()
        )
        _ = try await client.gatewayAccessToken()
        dying.kill("existing-key")
        let request = try await client.currentUserRequest()
        #expect(registers.snapshot() == 1)
        #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer token-2")
        #expect(request.value(forHTTPHeaderField: "X-AppAttest-Proof") != nil)
    }

    @Test
    func currentUserRequestInAPIKeyModeCarriesTheKeyAndNoProof() async throws {
        MockURLProtocol.handler = { request in response(request, status: 500, body: "{}") }
        let client = AppAIGatewayClient(
            appID: "machine-app",
            baseURL: URL(string: "https://gateway.test")!,
            authMode: .apiKey(key: "agw_machine-key"),
            endUserId: "customer-42",
            session: session()
        )
        let request = try await client.currentUserRequest()
        #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer agw_machine-key")
        #expect(request.value(forHTTPHeaderField: "X-End-User-ID") == "customer-42")
        #expect(request.value(forHTTPHeaderField: "X-AppAttest-Proof") == nil)
    }

    // MARK: The URL as the gateway reads it

    private struct URLGolden: Decodable {
        struct Fixed: Decodable {
            let appId: String
            let method: String
            let body: String
            let token: String
            let timestamp: String
            let nonce: String
        }
        struct Case: Decodable {
            let name: String
            let path: String
            let query: String?
            let pathAndQuery: String
            let clientData: String
        }
        let fixed: Fixed
        let cases: [Case]
    }

    /// The same file `test/request-proof.test.ts` reads, where each
    /// `pathAndQuery` is checked against the gateway runtime's own URL parser.
    private func urlGolden() throws -> URLGolden {
        let file = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appending(path: "Fixtures/request-proof-urls.json")
        return try JSONDecoder().decode(URLGolden.self, from: Data(contentsOf: file))
    }

    @Test
    func pathsAndQueriesAreSignedAsTheGatewayReadsThem() throws {
        let golden = try urlGolden()
        #expect(golden.cases.count >= 5)
        for fixture in golden.cases {
            let path = AppAIGatewayClient.whatwgPath(fixture.path)
            let pathAndQuery = fixture.query.map { "\(path)?\(AppAIGatewayClient.whatwgQuery($0))" } ?? path
            #expect(pathAndQuery == fixture.pathAndQuery, "\(fixture.name)")
            let clientData = AppAIGatewayClient.requestClientData(
                appID: golden.fixed.appId,
                method: golden.fixed.method,
                pathAndQuery: pathAndQuery,
                body: Data(golden.fixed.body.utf8),
                token: golden.fixed.token,
                timestamp: Int(golden.fixed.timestamp)!,
                nonce: golden.fixed.nonce
            )
            #expect(String(data: clientData, encoding: .utf8) == fixture.clientData, "\(fixture.name)")
            // Normalizing what is already normal changes nothing, so signing
            // the URL that is sent signs the same bytes again.
            #expect(AppAIGatewayClient.whatwgPath(path) == path, "\(fixture.name)")
        }
    }

    /// The URL that is sent is the normalized one, not only the string that
    /// is signed: a query with an apostrophe travels as `%27`, which is what
    /// the gateway's parser would have made of it anyway.
    @Test
    func theSentURLIsTheNormalizedOne() throws {
        let url = try #require(URL(string: "https://gateway.test/base/v1/apps/a/proxy/openai/./v1/x/../responses?q=it's"))
        let normalized = AppAIGatewayClient.whatwgNormalized(url)
        #expect(normalized.absoluteString == "https://gateway.test/base/v1/apps/a/proxy/openai/v1/responses?q=it%27s")
        #expect(AppAIGatewayClient.pathAndQuery(of: normalized) == "/base/v1/apps/a/proxy/openai/v1/responses?q=it%27s")
        let withPort = try #require(URL(string: "http://localhost:8787/v1/apps/a/me"))
        #expect(AppAIGatewayClient.whatwgNormalized(withPort).absoluteString == "http://localhost:8787/v1/apps/a/me")
    }

    @Test
    func aSignedRequestTravelsOnTheNormalizedURL() async throws {
        let signatures = SignatureLog()
        MockURLProtocol.handler = { request in
            if request.url!.path.hasSuffix("/auth/challenge") {
                return response(request, status: 200, body: #"{"challenge":"Y2hhbGxlbmdl"}"#)
            }
            return response(request, status: 200, body: #"{"access_token":"gateway-token","expires_in":3600,"verify_on":"every_request"}"#)
        }
        let client = AppAIGatewayClient(
            appID: "test-app",
            baseURL: URL(string: "https://gateway.test")!,
            authMode: .appAttestInstall,
            attestProvider: MockAttestProvider(signatures: signatures),
            credentialStore: MemoryCredentialStore(keyID: "existing-key"),
            session: session()
        )
        let request = try await client.authorizedRequest(
            provider: .openai, providerPath: "v1/./models/../responses", body: Data("{}".utf8)
        )
        #expect(request.url?.absoluteString == "https://gateway.test/v1/apps/test-app/proxy/openai/v1/responses")
        let parts = try #require(request.value(forHTTPHeaderField: "X-AppAttest-Proof")).split(separator: ".").map(String.init)
        let expected = AppAIGatewayClient.requestClientData(
            appID: "test-app", method: "POST",
            pathAndQuery: "/v1/apps/test-app/proxy/openai/v1/responses",
            body: Data("{}".utf8), token: "gateway-token",
            timestamp: try #require(Int(parts[1])), nonce: parts[2]
        ).sha256
        #expect(signatures.snapshot().last?.hash == expected)
    }

    /// An exchange already in flight when the token is discarded — a
    /// background refresh, say, answered under token_exchange — is not joined
    /// by the rebuilt request: that one starts its own exchange, signs with
    /// its token, and the overtaken result is never cached.
    @Test
    func aDiscardedTokenIsNotReplacedByAnExchangeAlreadyInFlight() async throws {
        let tokens = LockedCounter()
        // Assertion 1 is the overtaken exchange's, 2 the fresh exchange's,
        // and 3 the rebuilt request's own proof.
        let gates = AssertionGates(gated: [1, 2])
        MockURLProtocol.handler = { request in
            if request.url!.path.hasSuffix("/auth/challenge") {
                return response(request, status: 200, body: #"{"challenge":"Y2hhbGxlbmdl"}"#)
            }
            let issued = tokens.increment()
            let verifyOn = issued == 1 ? "token_exchange" : "every_request"
            return response(
                request,
                status: 200,
                body: "{\"access_token\":\"token-\(issued)\",\"expires_in\":3600,\"verify_on\":\"\(verifyOn)\"}"
            )
        }
        let client = AppAIGatewayClient(
            appID: "test-app",
            baseURL: URL(string: "https://gateway.test")!,
            authMode: .appAttestInstall,
            attestProvider: GatedAttestProvider(gates: gates),
            credentialStore: MemoryCredentialStore(keyID: "existing-key"),
            session: session()
        )
        let overtaken = Task { try await client.gatewayAccessToken() }
        #expect(try await gates.held(1))

        await client.discardAccessToken()
        let rebuilt = Task {
            try await client.authorizedRequest(provider: .openai, providerPath: "v1/responses", body: Data("{}".utf8))
        }
        // A second exchange started rather than joining the first.
        let started = try await gates.held(2)
        #expect(started)

        // The overtaken exchange finishes first, for the caller already on it.
        gates.open(1)
        #expect(try await overtaken.value == "token-1")
        // Asked while the fresh exchange is still held: a cached token-1 would
        // answer at once, and an uncached one joins the fresh exchange.
        let probe = Task { try await client.gatewayAccessToken() }
        gates.open(2)
        #expect(try await probe.value == "token-2")
        let request = try await rebuilt.value
        #expect(request.value(forHTTPHeaderField: "Authorization") == "Bearer token-2")
        #expect(request.value(forHTTPHeaderField: "X-AppAttest-Proof") != nil)
        // The cache holds the fresh token, and nothing exchanges again.
        #expect(try await client.gatewayAccessToken() == "token-2")
        #expect(tokens.snapshot() == 2)
    }

    // MARK: withAuthorizedRequest

    /// A gateway whose tokens are numbered in the order it mints them, each
    /// answering `verifyOn(n)`, and a client of it that verifies App Attest.
    private func numberedTokenClient(
        tokens: LockedCounter,
        signatures: SignatureLog = SignatureLog(),
        verifyOn: @escaping @Sendable (Int) -> String = { _ in "every_request" }
    ) -> AppAIGatewayClient {
        MockURLProtocol.handler = { request in
            if request.url!.path.hasSuffix("/auth/challenge") {
                return response(request, status: 200, body: #"{"challenge":"Y2hhbGxlbmdl"}"#)
            }
            let issued = tokens.increment()
            return response(
                request,
                status: 200,
                body: "{\"access_token\":\"token-\(issued)\",\"expires_in\":3600,\"verify_on\":\"\(verifyOn(issued))\"}"
            )
        }
        return AppAIGatewayClient(
            appID: "test-app",
            baseURL: URL(string: "https://gateway.test")!,
            authMode: .appAttestInstall,
            attestProvider: MockAttestProvider(signatures: signatures),
            credentialStore: MemoryCredentialStore(keyID: "existing-key"),
            session: session()
        )
    }

    /// A 401 is answered by a request built afresh, a new token and a new
    /// proof, never by re-sending the one already spent.
    @Test
    func withAuthorizedRequestRebuildsAndResendsOnceOnA401() async throws {
        let tokens = LockedCounter()
        let client = numberedTokenClient(tokens: tokens)
        let transport = FakeTransport(statuses: [401, 200])
        let body = Data(#"{"input":"hi"}"#.utf8)
        let (data, response) = try await client.withAuthorizedRequest(
            provider: .openai,
            providerPath: "v1/responses",
            body: body,
            contentType: "application/json",
            send: transport.send
        )
        #expect((response as? HTTPURLResponse)?.statusCode == 200)
        #expect(String(decoding: data, as: UTF8.self) == "attempt-2")
        let sent = transport.snapshot()
        #expect(sent.count == 2)
        #expect(tokens.snapshot() == 2)
        #expect(sent[0].value(forHTTPHeaderField: "Authorization") == "Bearer token-1")
        #expect(sent[1].value(forHTTPHeaderField: "Authorization") == "Bearer token-2")
        let firstProof = try #require(sent[0].value(forHTTPHeaderField: "X-AppAttest-Proof"))
        let secondProof = try #require(sent[1].value(forHTTPHeaderField: "X-AppAttest-Proof"))
        #expect(firstProof != secondProof)
        for request in sent {
            #expect(request.url?.absoluteString == "https://gateway.test/v1/apps/test-app/proxy/openai/v1/responses")
            #expect(request.httpBody == body)
            #expect(request.value(forHTTPHeaderField: "Content-Type") == "application/json")
        }
    }

    @Test
    func withAuthorizedRequestSendsOnceWhenTheFirstAnswerIsNot401() async throws {
        for status in [200, 403, 429, 500] {
            let tokens = LockedCounter()
            let client = numberedTokenClient(tokens: tokens)
            let transport = FakeTransport(statuses: [status, 200])
            let (data, response) = try await client.withAuthorizedRequest(
                provider: "openai",
                providerPath: "v1/responses",
                body: Data("{}".utf8),
                send: transport.send
            )
            #expect((response as? HTTPURLResponse)?.statusCode == status)
            #expect(String(decoding: data, as: UTF8.self) == "attempt-1")
            #expect(transport.snapshot().count == 1)
            #expect(tokens.snapshot() == 1)
        }
    }

    /// Transport failures are the app's: rethrown, not retried, and the token
    /// the client holds is kept.
    @Test
    func withAuthorizedRequestRethrowsWhatSendThrowsWithoutRetrying() async throws {
        let tokens = LockedCounter()
        let client = numberedTokenClient(tokens: tokens)
        let calls = LockedCounter()
        await #expect(throws: URLError.self) {
            _ = try await client.withAuthorizedRequest(
                provider: .openai,
                providerPath: "v1/responses",
                body: Data("{}".utf8)
            ) { (_: URLRequest) async throws -> (Data, URLResponse) in
                calls.increment()
                throw URLError(.notConnectedToInternet)
            }
        }
        #expect(calls.snapshot() == 1)
        #expect(try await client.gatewayAccessToken() == "token-1")
        #expect(tokens.snapshot() == 1)
    }

    /// A second refusal is real: returned to the caller, never a third send.
    @Test
    func withAuthorizedRequestReturnsASecond401WithoutAThirdSend() async throws {
        let tokens = LockedCounter()
        let client = numberedTokenClient(tokens: tokens)
        let transport = FakeTransport(statuses: [401, 401, 200])
        let (data, response) = try await client.withAuthorizedRequest(
            provider: .openai,
            providerPath: "v1/responses",
            body: Data("{}".utf8),
            send: transport.send
        )
        #expect((response as? HTTPURLResponse)?.statusCode == 401)
        #expect(String(decoding: data, as: UTF8.self) == "attempt-2")
        #expect(transport.snapshot().count == 2)
        #expect(tokens.snapshot() == 2)
    }

    /// The `assertion_required` case: a token cached under token_exchange
    /// sends the endpoint request unsigned, and the rebuilt one is signed.
    @Test
    func withAuthorizedRequestToAnEndpointPicksUpASwitchToEveryRequest() async throws {
        let tokens = LockedCounter()
        let signatures = SignatureLog()
        let client = numberedTokenClient(
            tokens: tokens,
            signatures: signatures,
            verifyOn: { $0 == 1 ? "token_exchange" : "every_request" }
        )
        let transport = FakeTransport(statuses: [401, 200])
        let (_, response) = try await client.withAuthorizedRequest(
            endpointSlug: "chat",
            body: Data("{}".utf8),
            send: transport.send
        )
        #expect((response as? HTTPURLResponse)?.statusCode == 200)
        let sent = transport.snapshot()
        #expect(sent.count == 2)
        #expect(sent.allSatisfy { $0.url?.absoluteString == "https://gateway.test/v1/apps/test-app/endpoints/chat" })
        #expect(sent[0].value(forHTTPHeaderField: "Authorization") == "Bearer token-1")
        #expect(sent[0].value(forHTTPHeaderField: "X-AppAttest-Proof") == nil)
        #expect(sent[1].value(forHTTPHeaderField: "Authorization") == "Bearer token-2")
        #expect(sent[1].value(forHTTPHeaderField: "X-AppAttest-Proof") != nil)
    }

    @Test
    func withCurrentUserRequestRebuildsMeOnA401() async throws {
        let tokens = LockedCounter()
        let client = numberedTokenClient(tokens: tokens)
        let transport = FakeTransport(statuses: [401, 200])
        let (_, response) = try await client.withCurrentUserRequest(send: transport.send)
        #expect((response as? HTTPURLResponse)?.statusCode == 200)
        let sent = transport.snapshot()
        #expect(sent.count == 2)
        for request in sent {
            #expect(request.httpMethod == "GET")
            #expect(request.url?.absoluteString == "https://gateway.test/v1/apps/test-app/me")
        }
        #expect(sent[1].value(forHTTPHeaderField: "Authorization") == "Bearer token-2")
        #expect(
            sent[0].value(forHTTPHeaderField: "X-AppAttest-Proof")
                != sent[1].value(forHTTPHeaderField: "X-AppAttest-Proof")
        )
    }

    /// A body that is a stream, as `URLSession.bytes(for:)` returns: the
    /// helper is generic over it, and hands back the second attempt's stream.
    @Test
    func withAuthorizedRequestPassesAStreamingBodyThrough() async throws {
        let tokens = LockedCounter()
        let client = numberedTokenClient(tokens: tokens)
        let calls = LockedCounter()
        let (stream, response) = try await client.withAuthorizedRequest(
            provider: .anthropic,
            providerPath: "v1/messages",
            body: Data(#"{"stream":true}"#.utf8),
            contentType: "application/json"
        ) { request -> (AsyncStream<String>, URLResponse) in
            let attempt = calls.increment()
            let status = attempt == 1 ? 401 : 200
            let stream = AsyncStream<String> { continuation in
                continuation.yield("event-\(attempt)-a")
                continuation.yield("event-\(attempt)-b")
                continuation.finish()
            }
            return (stream, HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: nil)!)
        }
        #expect((response as? HTTPURLResponse)?.statusCode == 200)
        var events: [String] = []
        for await event in stream { events.append(event) }
        #expect(events == ["event-2-a", "event-2-b"])
        #expect(calls.snapshot() == 2)
    }
}

/// An App Attest provider whose numbered `generateAssertion` calls wait until
/// the test opens them, to hold a token exchange part way through.
struct GatedAttestProvider: AppAttestProviding {
    let gates: AssertionGates
    var isSupported: Bool { true }
    func generateKey() async throws -> String { "generated-key" }
    func attestKey(_ keyID: String, clientDataHash: Data) async throws -> Data { Data("attestation".utf8) }
    func generateAssertion(_ keyID: String, clientDataHash: Data) async throws -> Data {
        await gates.pass()
        return Data("assertion".utf8)
    }
}

final class AssertionGates: @unchecked Sendable {
    private let lock = NSLock()
    private let gated: Set<Int>
    private var calls = 0
    private var opened: Set<Int> = []
    private var waiting: [Int: CheckedContinuation<Void, Never>] = [:]

    /// Calls numbered in `gated`, from 1, wait for `open`; the rest pass.
    init(gated: Set<Int>) { self.gated = gated }

    func pass() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            let resumeNow: Bool = lock.withLock {
                calls += 1
                guard gated.contains(calls), !opened.contains(calls) else { return true }
                waiting[calls] = continuation
                return false
            }
            if resumeNow { continuation.resume() }
        }
    }

    func open(_ call: Int) {
        let continuation = lock.withLock {
            opened.insert(call)
            return waiting.removeValue(forKey: call)
        }
        continuation?.resume()
    }

    /// Waits, for a second at most, until call `call` is held at its gate.
    func held(_ call: Int) async throws -> Bool {
        for _ in 0..<1000 {
            if lock.withLock({ waiting[call] != nil }) { return true }
            try await Task.sleep(for: .milliseconds(1))
        }
        return false
    }
}

/// Stands in for the app's transport: records each request it is handed and
/// answers the statuses it was given in turn, the last one repeating, with a
/// body naming the attempt.
final class FakeTransport: @unchecked Sendable {
    private let lock = NSLock()
    private let statuses: [Int]
    private var requests: [URLRequest] = []

    init(statuses: [Int]) { self.statuses = statuses }

    @Sendable
    func send(_ request: URLRequest) async throws -> (Data, URLResponse) {
        lock.withLock {
            requests.append(request)
            let attempt = requests.count
            let status = statuses[min(attempt, statuses.count) - 1]
            return (
                Data("attempt-\(attempt)".utf8),
                HTTPURLResponse(url: request.url!, statusCode: status, httpVersion: nil, headerFields: nil)!
            )
        }
    }

    func snapshot() -> [URLRequest] { lock.withLock { requests } }
}
