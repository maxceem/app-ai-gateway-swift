# AppAIGateway

The Swift client for [App AI Gateway](https://appaigateway.com). It handles
App Attest registration, the gateway token exchange and refresh, and the
headers every request needs, so your iOS app can call AI providers through the
gateway without holding a provider key.

Add `https://github.com/maxceem/app-ai-gateway-swift` in Xcode's **File → Add
Package Dependencies**, or add this dependency to `Package.swift`:

```swift
.package(url: "https://github.com/maxceem/app-ai-gateway-swift", from: "1.4.1")
```

Add the `AppAIGateway` product to your target.

```swift
import AppAIGateway

let gateway = AppAIGatewayClient(
    appID: "example-app-a1b2c3",
    baseURL: URL(string: "https://api.appaigateway.com")!,
    authMode: .appAttestInstall
)

let (data, response) = try await gateway.withAuthorizedRequest(
    provider: .openai,
    providerPath: "v1/responses",
    body: Data(#"{"model":"gpt-5.6-sol","input":"Say hello."}"#.utf8),
    contentType: "application/json"
) { try await URLSession.shared.data(for: $0) }
if let error = GatewayError(response: response as! HTTPURLResponse, body: data) {
    throw error
}
```

`withAuthorizedRequest` builds the request and hands it to your closure, which
sends it. The package never performs the request itself, so any session,
configuration or networking library works. To stream, send it with
`bytes(for:)`, which returns once the response headers arrive, before the body:

```swift
let (bytes, response) = try await gateway.withAuthorizedRequest(
    provider: .openai,
    providerPath: "v1/responses",
    body: Data(#"{"model":"gpt-5.6-sol","input":"Say hello.","stream":true}"#.utf8),
    contentType: "application/json"
) { try await URLSession.shared.bytes(for: $0) }
let http = response as! HTTPURLResponse
guard (200..<300).contains(http.statusCode) else {
    let body = try await bytes.reduce(into: Data()) { $0.append($1) }
    throw GatewayError(response: http, body: body)!
}
for try await line in bytes.lines {
    print(line)
}
```

If the gateway answers `401`, the helper discards its token, builds the
request again with a fresh token and, where requests are signed, a fresh
proof, and sends it once more. That recovers from an expired gateway token,
from an App Attest key the gateway no longer knows (the fresh exchange
re-registers it), and from an app switched to verify every request after the
token was cached. A thrown error and every other status, `403` and `429`
included, come back to you untouched. `authorizedRequest` remains available
for apps that want to drive the retry themselves.

In the App Attest modes the gateway decides whether requests are signed. Each
app has a "Verify App Attest on" setting, and the token exchange answers with
it as `verify_on`:

- `every_request` (the default for new apps): each request gets an
  `X-AppAttest-Proof` header, an assertion the device's App Attest key made
  over exactly that method, URL, body and gateway token. Pass the body to
  `withAuthorizedRequest` (or `authorizedRequest`) and send the request as it
  comes back. Changing the body or the URL afterwards invalidates the proof,
  and the gateway refuses the request with `attest_failed`. Other headers may
  be added. Build a new request for every send: each proof is accepted once.
- `token_exchange`: the assertion is checked once per hourly token, and
  requests carry only the token. A gateway that sends no `verify_on` is
  treated the same way.

Build requests through the package in either case, so a change of the
setting needs no change in your app.

To show the caller where they stand against your app's limits, send
`withCurrentUserRequest`, a `GET /v1/apps/{app}/me` signed the same way and
resent once on a `401` (`currentUserRequest()` builds it alone). Build it
there rather than from a URL of your own: on an app that verifies every
request, a request without a proof is refused with `assertion_required`, and editing
a signed request's URL breaks its proof.

### Upgrading to 1.4

1.4 is required by apps that verify App Attest on every request.
`authorizedRequest` now takes `body:` and `contentType:`, both optional, so
existing calls compile unchanged; move a body you used to assign to `httpBody`
into the call, because a body set afterwards is outside the proof. API-key
modes are unchanged and send no proof. Since 1.4.1, `withAuthorizedRequest`
recovers from `auth_required` and `assertion_required`, both `401`, on its
own. On a request built by the package and sent with its headers intact,
`assertion_required` means the app was switched to verify every request after
the client's token was issued; the fresh exchange says so, and the rebuilt
request is signed. A request you assemble from `gatewayAccessToken()` yourself
gets it whenever the app verifies every request. If you send requests built
with `authorizedRequest`, handle a `401` yourself: call `discardAccessToken()`
and build the request again, once. A `403 attest_failed` that persists across
a rebuilt request is cleared the same way.

Requires iOS 16 or macOS 13. App Attest needs a real device.

- Guide: https://docs.appaigateway.com/integrate/ios/
- Errors and limits: https://docs.appaigateway.com/integrate/errors/

This repository is published from the `app-ai-gateway-swift` directory of
[maxceem/app-ai-gateway](https://github.com/maxceem/app-ai-gateway). Open
issues and pull requests there.

To release a new version, update `app-ai-gateway-swift/VERSION` in the source
repository and merge the pull request into `main`. After tests pass, the
publishing workflow syncs this repository and creates the matching immutable
version tag. Changes without a version bump sync `main` without changing any
released version. The current version is `1.4.1`. A failed publish can be retried
with the source repository's **Publish Swift package** workflow.

Licensed under the Apache License 2.0.
