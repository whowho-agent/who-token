import Foundation
import NIOConcurrencyHelpers
import NIOCore
import NIOPosix
import NIOSSL
import Security
import Testing
import TokenKit
@testable import ProxyKit

struct SoftwareIdentityProvider: ClientIdentityProvider {
    let recorder: SignRecorder

    func identity(for host: String) async throws -> ClientIdentity? {
        let certificate = try TokenCertificate(keyID: Data([1]), label: "test", der: fixture("client-auth", "der"))
        let key = TokenPrivateKey(
            slot: 0, keyID: certificate.keyID, supported: SignatureAlgorithm.allCases,
            onSign: { algorithm, _ in recorder.record(algorithm) },
            signer: try softwareSigner()
        )
        return ClientIdentity(certificate: certificate, privateKey: key)
    }
}

/// Client speaking to the proxy like WebKit does: CONNECT, then TLS inside the tunnel.
/// (URLSession can't be used here: CFNetwork never proxies loopback addresses.)
enum ProxyClient {
    static func get(host: String, port: Int, proxyPort: Int, trustRootsDER: [Data], proxyAuthorization: String? = nil) async throws -> String {
        var tls = TLSConfiguration.makeClientConfiguration()
        tls.trustRoots = .certificates(try trustRootsDER.map { try NIOSSLCertificate(bytes: Array($0), format: .der) })
        let context = try NIOSSLContext(configuration: tls)
        let collector = ResponseCollector()
        let connectDone = NIOLockedValueBox<EventLoopPromise<Void>?>(nil)

        let channel = try await ClientBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    let promise = channel.eventLoop.makePromise(of: Void.self)
                    connectDone.withLockedValue { $0 = promise }
                    try channel.pipeline.syncOperations.addHandler(ConnectResponseHandler(done: promise))
                    try channel.pipeline.syncOperations.addHandler(collector)
                }
            }
            .connect(host: "127.0.0.1", port: proxyPort)
            .get()
        let auth = proxyAuthorization.map { "Proxy-Authorization: \($0)\r\n" } ?? ""
        try await channel.writeAndFlush(ByteBuffer(string: "CONNECT \(host):\(port) HTTP/1.1\r\nHost: \(host):\(port)\r\n\(auth)\r\n")).get()
        try await connectDone.withLockedValue { $0! }.futureResult.get()

        try await channel.eventLoop.submit {
            try channel.pipeline.syncOperations.addHandler(NIOSSLClientHandler(context: context, serverHostname: nil), position: .first)
        }.get()
        try await channel.writeAndFlush(ByteBuffer(string: "GET / HTTP/1.1\r\nHost: \(host)\r\nConnection: close\r\n\r\n")).get()
        return String(decoding: try await collector.result.get(), as: UTF8.self)
    }
}

/// Consumes the proxy's "200 Connection Established" and gets out of the way.
private final class ConnectResponseHandler: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    private let done: EventLoopPromise<Void>
    private var buffer = ByteBuffer()

    init(done: EventLoopPromise<Void>) { self.done = done }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var chunk = unwrapInboundIn(data)
        buffer.writeBuffer(&chunk)
        let text = String(buffer: buffer)
        guard text.contains("\r\n\r\n") else { return }
        context.pipeline.syncOperations.removeHandler(context: context, promise: nil)
        if text.hasPrefix("HTTP/1.1 200") { done.succeed() } else { done.fail(ChannelError.inappropriateOperationForState) }
    }
}

final class EventRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [ProxyEvent] = []
    func record(_ event: ProxyEvent) { lock.withLock { stored.append(event) } }
    var events: [ProxyEvent] { lock.withLock { stored } }
}

@Suite struct LocalProxyServerTests {
    @Test func interceptsHostAndAuthenticatesWithTokenKey() async throws {
        let server = try await startServer()
        defer { server.close(promise: nil) }
        let serverPort = try #require(server.localAddress?.port)

        let signs = SignRecorder()
        let events = EventRecorder()
        let proxy = try await LocalProxyServer.start(.init(
            shouldIntercept: { $0 == "127.0.0.1" },
            identityProvider: SoftwareIdentityProvider(recorder: signs),
            extraTrustRootsPEM: [try fixture("server", "pem")],
            onEvent: events.record
        ))
        defer { Task { await proxy.stop() } }

        let response = try await ProxyClient.get(
            host: "127.0.0.1", port: serverPort, proxyPort: proxy.port, trustRootsDER: [proxy.authority.caCertificateDER]
        )

        #expect(response.hasPrefix("HTTP/1.0 200"))
        #expect(response.contains("Test Client"))
        #expect(signs.recorded.first == .rsaPssRsaeSha256)
        #expect(events.events.contains { if case .intercept(_, _, true) = $0 { true } else { false } })
    }

    @Test func tunnelsOtherHostsWithoutDecryption() async throws {
        let server = try await startServer(requireClientCertificate: false)
        defer { server.close(promise: nil) }
        let serverPort = try #require(server.localAddress?.port)

        let signs = SignRecorder()
        let events = EventRecorder()
        let proxy = try await LocalProxyServer.start(.init(
            shouldIntercept: { _ in false },
            identityProvider: SoftwareIdentityProvider(recorder: signs),
            onEvent: events.record
        ))
        defer { Task { await proxy.stop() } }

        // The client sees the real server certificate, not the proxy CA.
        let pem = String(decoding: try fixture("server", "pem"), as: UTF8.self)
            .components(separatedBy: "\n").filter { !$0.hasPrefix("-----") }.joined()
        let response = try await ProxyClient.get(
            host: "127.0.0.1", port: serverPort, proxyPort: proxy.port, trustRootsDER: [try #require(Data(base64Encoded: pem))]
        )

        #expect(response.hasPrefix("HTTP/1.0 200"))
        #expect(response.contains("client=none"))
        #expect(signs.recorded.isEmpty)
        #expect(events.events.contains { if case .tunnel = $0 { true } else { false } })
    }

    @Test func issuesLeafWithIPAddressSAN() throws {
        let authority = try MitmCertificateAuthority()
        let leaf = try #require(SecCertificateCreateWithData(nil, try authority.issueLeaf(for: "192.0.2.10") as CFData))
        let ca = try #require(SecCertificateCreateWithData(nil, authority.caCertificateDER as CFData))
        var trust: SecTrust?
        SecTrustCreateWithCertificates(leaf, SecPolicyCreateSSL(true, "192.0.2.10" as CFString), &trust)
        let serverTrust = try #require(trust)
        SecTrustSetAnchorCertificates(serverTrust, [ca] as CFArray)
        #expect(SecTrustEvaluateWithError(serverTrust, nil))
    }

    @Test func parsesConnectAuthority() {
        #expect(ProxyFrontHandler.hostPort("example.com:8443", defaultPort: 443)! == ("example.com", 8443))
        #expect(ProxyFrontHandler.hostPort("example.com", defaultPort: 443)! == ("example.com", 443))
        #expect(ProxyFrontHandler.hostPort("[::1]:9000", defaultPort: 443)! == ("::1", 9000))
    }
}
