import CryptoTokenKit
import TokenKit

/// CryptoTokenKit driver for Rutoken: makes certificates registered by the app usable as system
/// identities (WKWebView client certificates); signatures are produced by the token via PKCS#11.
final class TokenDriver: TKTokenDriver, TKTokenDriverDelegate {
    /// The USB token is visible to PKCS#11 only while RtPcsc reader discovery runs in this process.
    static let readerMonitor: ReaderMonitor = {
        let monitor = ReaderMonitor()
        Task {
            for await readers in await monitor.start() {
                ExtensionLog.append("readers: \(readers.map(\.name))")
            }
        }
        return monitor
    }()

    func tokenDriver(_ driver: TKTokenDriver, tokenFor configuration: TKToken.Configuration) throws -> TKToken {
        _ = Self.readerMonitor
        ExtensionLog.append("tokenFor \(configuration.instanceID)")
        return RutokenToken(tokenDriver: self, instanceID: configuration.instanceID)
    }
}

final class RutokenToken: TKToken, TKTokenDelegate {
    /// One PKCS#11 owner per extension process.
    static let service: TokenService? = try? TokenService()

    /// Token serial number; the app registers configurations under it.
    let serialNumber: String

    override init(tokenDriver: TKTokenDriver, instanceID: String) {
        serialNumber = instanceID
        super.init(tokenDriver: tokenDriver, instanceID: instanceID)
        delegate = self
    }

    func createSession(_ token: TKToken) throws -> TKTokenSession {
        let session = RutokenTokenSession(token: token)
        session.delegate = session
        return session
    }

    func login(pin: String) throws {
        let slot = try currentSlot()
        try blocking { try await Self.service?.login(slot: slot, pin: pin) }
    }

    func isLoggedIn() -> Bool {
        guard let slot = try? currentSlot() else { return false }
        return (try? blocking { await Self.service?.isLoggedIn(slot: slot) ?? false }) ?? false
    }

    func sign(_ digest: Data, keyID: Data, algorithm: DigestSignatureAlgorithm) throws -> Data {
        let slot = try currentSlot()
        return try blocking {
            guard let service = Self.service else { throw TKError(.objectNotFound) }
            return try await service.signDigest(digest, keyID: keyID, algorithm: algorithm, slot: slot)
        }
    }

    private func currentSlot() throws -> UInt {
        let serial = serialNumber
        // Right after the extension starts, reader discovery may not have found the token yet.
        let slot = try blocking { () -> UInt? in
            for _ in 0..<30 {
                if let slot = try await Self.service?.slot(serialNumber: serial) { return slot }
                try await Task.sleep(for: .milliseconds(100))
            }
            return nil
        }
        guard let slot else {
            ExtensionLog.append("token \(serial) not connected")
            throw TKError(.tokenNotFound)
        }
        return slot
    }
}

/// TKTokenSession callbacks are synchronous; TokenService is an actor on its own queue,
/// so waiting here cannot deadlock it.
func blocking<T: Sendable>(_ operation: @escaping @Sendable () async throws -> T) throws -> T {
    let semaphore = DispatchSemaphore(value: 0)
    nonisolated(unsafe) var result: Result<T, Error>!
    Task {
        do { result = .success(try await operation()) } catch { result = .failure(error) }
        semaphore.signal()
    }
    semaphore.wait()
    return try result.get()
}
