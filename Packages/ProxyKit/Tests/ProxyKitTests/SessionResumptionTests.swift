import Foundation
import NIOCore
import NIOSSL
import Testing
import TokenKit
@testable import ProxyKit

private func softwareKey(_ recorder: SignRecorder) throws -> (TokenCertificate, TokenPrivateKey) {
    let certificate = try TokenCertificate(keyID: Data([1]), label: "test", der: fixture("client-auth", "der"))
    let key = TokenPrivateKey(
        slot: 0, keyID: certificate.keyID, supported: SignatureAlgorithm.allCases,
        onSign: { algorithm, _ in recorder.record(algorithm) },
        signer: try softwareSigner()
    )
    return (certificate, key)
}

@Suite struct SessionResumptionTests {
    @Test(arguments: [TLSVersionChoice.tls13, .tls12])
    func secondConnectionResumesWithoutSigning(version: TLSVersionChoice) async throws {
        let server = try await startServer()
        defer { server.close(promise: nil) }
        let url = URL(string: "https://127.0.0.1:\(try #require(server.localAddress?.port))/")!
        let recorder = SignRecorder()
        let (certificate, key) = try softwareKey(recorder)
        let cache = UpstreamSessionCache()

        func get() async throws -> MTLSResponse {
            try await MTLSClient.get(
                url, certificate: certificate, privateKey: key,
                extraTrustRootsPEM: [try fixture("server", "pem")], version: version, sessionCache: cache
            )
        }

        let first = try await get()
        let second = try await get()
        #expect(recorder.recorded.count == 1)
        // The resumed session still authenticates the client: the server reports the certificate.
        #expect(first.body.contains("Test Client") && second.body.contains("Test Client"))
        #expect(second.tlsVersion.contains(version == .tls13 ? "13" : "12"))
        #expect(cache.count == 1)

        cache.removeAll()
        _ = try await get()
        #expect(recorder.recorded.count == 2)
    }

    @Test func withoutCacheEveryConnectionSigns() async throws {
        let server = try await startServer()
        defer { server.close(promise: nil) }
        let url = URL(string: "https://127.0.0.1:\(try #require(server.localAddress?.port))/")!
        let recorder = SignRecorder()
        let (certificate, key) = try softwareKey(recorder)
        for _ in 0..<2 {
            _ = try await MTLSClient.get(url, certificate: certificate, privateKey: key, extraTrustRootsPEM: [try fixture("server", "pem")])
        }
        #expect(recorder.recorded.count == 2)
    }

    @Test(arguments: [TLSVersion.tlsv13, .tlsv12])
    func proxyResumesUpstreamSessions(serverVersion: TLSVersion) async throws {
        let server = try await startServer(maximumTLSVersion: serverVersion)
        defer { server.close(promise: nil) }
        let serverPort = try #require(server.localAddress?.port)
        let signs = SignRecorder()
        let proxy = try await LocalProxyServer.start(.init(
            shouldIntercept: { _ in true },
            identityProvider: SoftwareIdentityProvider(recorder: signs),
            extraTrustRootsPEM: [try fixture("server", "pem")]
        ))
        defer { Task { await proxy.stop() } }

        func get() async throws -> String {
            try await ProxyClient.get(
                host: "127.0.0.1", port: serverPort, proxyPort: proxy.port, trustRootsDER: [proxy.authority.caCertificateDER]
            )
        }

        // Sequential, like a page load followed by navigation.
        #expect(try await get().contains("Test Client"))
        #expect(try await get().contains("Test Client"))
        #expect(signs.recorded.count == 1)

        // Sign-out: the next connection must use the token again.
        proxy.sessionCache?.removeAll()
        #expect(try await get().contains("Test Client"))
        #expect(signs.recorded.count == 2)
    }

    @Test func parallelFirstConnectionsShareOneSignature() async throws {
        let server = try await startServer()
        defer { server.close(promise: nil) }
        let serverPort = try #require(server.localAddress?.port)
        let signs = SignRecorder()
        let proxy = try await LocalProxyServer.start(.init(
            shouldIntercept: { _ in true },
            identityProvider: SoftwareIdentityProvider(recorder: signs),
            extraTrustRootsPEM: [try fixture("server", "pem")]
        ))
        defer { Task { await proxy.stop() } }
        let caDER = proxy.authority.caCertificateDER
        let proxyPort = proxy.port

        // WebKit opens several connections to a host at once.
        let responses = try await withThrowingTaskGroup(of: String.self) { group in
            for _ in 0..<4 {
                group.addTask {
                    try await ProxyClient.get(host: "127.0.0.1", port: serverPort, proxyPort: proxyPort, trustRootsDER: [caDER])
                }
            }
            return try await group.reduce(into: []) { $0.append($1) }
        }
        #expect(responses.count == 4 && responses.allSatisfy { $0.contains("Test Client") })
        #expect(signs.recorded.count == 1)
    }

    @Test func waitersAreReleasedWhenLeaderGetsNoSession() async throws {
        let cache = UpstreamSessionCache()
        let key = UpstreamSessionCache.Key(host: "example.test", port: 443, identity: nil)
        let leader = await cache.checkout(key)
        #expect(leader.leaderID != nil && leader.session == nil)

        let follower = Task { await cache.checkout(key) }
        try await Task.sleep(for: .milliseconds(50))
        leader.finish()
        let lease = await follower.value
        #expect(lease.session == nil && lease.leaderID == nil)
    }

    @Test func waitersGiveUpAfterTimeout() async throws {
        let cache = UpstreamSessionCache(firstHandshakeWait: .milliseconds(100))
        let key = UpstreamSessionCache.Key(host: "example.test", port: 443, identity: nil)
        let leader = await cache.checkout(key)
        let start = ContinuousClock.now
        let lease = await cache.checkout(key)
        #expect(lease.session == nil)
        #expect(ContinuousClock.now - start < .seconds(5))
        leader.finish()
    }
}
