import Foundation

/// This package's name and version, sent to the gateway as `X-Client-SDK` on
/// every request the client sends or builds, so the gateway can tell which
/// release of the package an install runs.
///
/// A diagnostic, not a credential: it is not part of any App Attest proof,
/// and the gateway records it only where it is exactly `<name>/<version>`.
enum ClientSDK {
    static let headerField = "X-Client-SDK"
    static let name = "app-ai-gateway-swift"
    /// The release this source is. The package's `VERSION` file, which a
    /// release is cut from, is the source of truth; a test fails until this
    /// matches it, so bump both together.
    static let version = "1.8.0"
    static let headerValue = "\(name)/\(version)"
}
