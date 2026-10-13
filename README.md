# AppAIGateway

The Swift client for [App AI Gateway](https://appaigateway.com). It handles
App Attest registration, the gateway token exchange and refresh, and the
headers every request needs, so your iOS app can call AI providers through the
gateway without holding a provider key.

Add `https://github.com/maxceem/app-ai-gateway-swift` in Xcode's **File → Add
Package Dependencies**, or add this dependency to `Package.swift`:

```swift
.package(url: "https://github.com/maxceem/app-ai-gateway-swift", from: "2.0.0")
```

Add the `AppAIGateway` product to your target.

```swift
import AppAIGateway

let gateway = AppAIGatewayClient(
    appID: "example-app-a1b2c3",
    baseURL: URL(string: "https://api.appaigateway.com")!,
    authMode: .appAttestInstall
)

let request = try await gateway.authorizedRequest(
    provider: .openai,
    providerPath: "v1/responses",
    body: Data(#"{"model":"gpt-5.6-sol","input":"Say hello."}"#.utf8),
    contentType: "application/json"
)
let (data, _) = try await URLSession.shared.data(for: request)
```

In the App Attest modes every request is signed: `authorizedRequest` adds an
`X-AppAttest-Proof` header, an assertion the device's App Attest key made over
exactly that method, URL, body and gateway token. Pass the body to
`authorizedRequest` and send the request as it comes back. Changing the body
or the URL afterwards invalidates the proof, and the gateway refuses the
request with `attest_failed`. Other headers may be added. Build a new request
for every send: each proof is accepted once.

### Upgrading from 1.x

2.0 is required by gateways that verify every request. `authorizedRequest`
now takes `body:` and `contentType:`; move a body you used to assign to
`httpBody` into the call. API-key modes are unchanged and send no proof. If
your app sends a request and is refused with `attest_failed` or
`auth_required`, call `discardAccessToken()` and build the request again.

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
released version. The current version is `2.0.0`. A failed publish can be retried
with the source repository's **Publish Swift package** workflow.

Licensed under the Apache License 2.0.
