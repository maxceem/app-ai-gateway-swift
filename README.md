# AppAIGateway

The Swift client for [App AI Gateway](https://appaigateway.com). It handles
App Attest registration, the gateway token exchange and refresh, and the
headers every request needs, so your iOS app can call AI providers through the
gateway without holding a provider key.

Add `https://github.com/maxceem/app-ai-gateway-swift` in Xcode's **File → Add
Package Dependencies**, or add this dependency to `Package.swift`:

```swift
.package(url: "https://github.com/maxceem/app-ai-gateway-swift", from: "1.0.0")
```

Add the `AppAIGateway` product to your target.

```swift
import AppAIGateway

let gateway = AppAIGatewayClient(
    appID: "example-app-a1b2c3",
    baseURL: URL(string: "https://api.appaigateway.com")!,
    authMode: .appAttestInstall
)

var request = try await gateway.authorizedRequest(provider: .openai, providerPath: "v1/responses")
request.setValue("application/json", forHTTPHeaderField: "Content-Type")
request.httpBody = Data(#"{"model":"gpt-5.6","input":"Say hello."}"#.utf8)
let (data, _) = try await URLSession.shared.data(for: request)
```

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
released version. The initial version is `1.0.0`. A failed publish can be retried
with the source repository's **Publish Swift package** workflow.

Licensed under the Apache License 2.0.
