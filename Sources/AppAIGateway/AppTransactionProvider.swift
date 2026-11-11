import Foundation

#if os(iOS)
import StoreKit
#endif

/// Supplies the App Store's signed record of this app's purchase — its
/// `AppTransaction` — for the App Attest token exchange.
///
/// The gateway reads the Apple Account the transaction names, so an app that
/// measures its per-user budget over the Apple Account counts the same person
/// across reinstalls and devices, where an attested key counts only one
/// install. The gateway verifies the signature itself, which is why the
/// signed form travels, never fields decoded from it on the device.
public protocol AppTransactionProviding: Sendable {
    /// The transaction as Apple signed it, a JWS, or `nil` where there is none
    /// to send. Never throws and never prompts: an exchange without one goes
    /// ahead, and the gateway counts the install instead.
    func jwsRepresentation() async -> String?
}

/// The `AppTransaction` StoreKit already holds for this app.
///
/// Reads `AppTransaction.shared` alone, never `refresh()`: refreshing asks the
/// user to sign in to the App Store, and nothing the gateway does is worth
/// interrupting them for. An unverified transaction is sent all the same — the
/// gateway checks the signature and simply does not count one it rejects, such
/// as one Xcode's StoreKit configuration signed.
///
/// The value is fetched on every exchange, about once an hour, which costs
/// little: StoreKit caches it. Elsewhere than iOS, where this package's own
/// App Attest provider is unsupported too, it supplies nothing.
public struct SystemAppTransactionProvider: AppTransactionProviding {
    /// How long an exchange waits for StoreKit before going ahead without the
    /// transaction. Fetching it can mean a trip to the App Store, and a token
    /// exchange held up by one would stall every request the app makes.
    public static let defaultTimeout: Duration = .seconds(5)

    private let timeout: Duration

    public init(timeout: Duration = SystemAppTransactionProvider.defaultTimeout) {
        self.timeout = timeout
    }

    public func jwsRepresentation() async -> String? {
        #if os(iOS)
        return await Self.first(within: timeout) {
            try? await AppTransaction.shared.jwsRepresentation
        }
        #else
        return nil
        #endif
    }

    /// What `operation` returns, or `nil` once `timeout` has passed without it.
    ///
    /// A task group cannot do this: it waits for every child before it
    /// returns, and StoreKit's fetch is not known to stop when cancelled. The
    /// operation is left to finish on its own instead, its late result
    /// dropped.
    static func first(
        within timeout: Duration,
        _ operation: @escaping @Sendable () async -> String?
    ) async -> String? {
        await withCheckedContinuation { continuation in
            let once = ResumeOnce(continuation)
            let timer = Task {
                try? await Task.sleep(for: timeout)
                once.resume(returning: nil)
            }
            Task {
                once.resume(returning: await operation())
                timer.cancel()
            }
        }
    }
}

/// Resumes a continuation the first time it is asked to and ignores every
/// later request, for a race whose loser still finishes.
private final class ResumeOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<String?, Never>?

    init(_ continuation: CheckedContinuation<String?, Never>) {
        self.continuation = continuation
    }

    func resume(returning value: String?) {
        let pending: CheckedContinuation<String?, Never>? = lock.withLock {
            defer { continuation = nil }
            return continuation
        }
        pending?.resume(returning: value)
    }
}
