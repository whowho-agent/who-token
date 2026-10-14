import Foundation
import NIOCore
import NIOPosix
import NIOSSL
import Security
import Testing
import TokenKit
@testable import ProxyKit

func fixture(_ name: String, _ ext: String) throws -> Data {
    let url = try #require(Bundle.module.url(forResource: name, withExtension: ext, subdirectory: "Fixtures"))
    return try Data(contentsOf: url)
}

/// Software stand-in for the token: signs with the fixture RSA key through Security.framework.
func softwareSigner() throws -> TokenPrivateKey.Signer {
    let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPrivate]
    let key = try #require(SecKeyCreateWithData(try fixture("client-auth-key.pkcs1", "der") as CFData, attributes as CFDictionary, nil))
    nonisolated(unsafe) let unsafeKey = key
    return { message, algorithm in
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(unsafeKey, algorithm.secKeyAlgorithm, message as CFData, &error) else {
            throw error!.takeRetainedValue()
        }
        return signature as Data
    }
}

final class SignRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var algorithms: [TokenKit.SignatureAlgorithm] = []
    func record(_ algorithm: TokenKit.SignatureAlgorithm) { lock.withLock { algorithms.append(algorithm) } }
    var recorded: [TokenKit.SignatureAlgorithm] { lock.withLock { algorithms } }
}

/// Minimal mTLS server: requires a client certificate issued by `client-ca.pem` and answers with its CN.
private final class EchoClientCertHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let channel = context.channel
        channel.pipeline.handler(type: NIOSSLServerHandler.self).whenSuccess { tls in
            let peer = tls.peerCertificate.map { String(describing: $0) } ?? "none"
            let body = "client=\(peer)"
            let response = "HTTP/1.0 200 OK\r\nContent-Length: \(body.utf8.count)\r\n\r\n\(body)"
            channel.writeAndFlush(ByteBuffer(string: response)).whenComplete { _ in channel.close(promise: nil) }
        }
    }
}

func startServer(requireClientCertificate: Bool = true, maximumTLSVersion: TLSVersion? = nil) async throws -> Channel {
    var configuration = TLSConfiguration.makeServerConfiguration(
        certificateChain: try NIOSSLCertificate.fromPEMBytes(Array(fixture("server", "pem"))).map { .certificate($0) },
        privateKey: .privateKey(try NIOSSLPrivateKey(bytes: Array(fixture("server-key", "pem")), format: .pem))
    )
    configuration.certificateVerification = requireClientCertificate ? .noHostnameVerification : .none
    configuration.trustRoots = .certificates(try NIOSSLCertificate.fromPEMBytes(Array(fixture("client-ca", "pem"))))
    configuration.maximumTLSVersion = maximumTLSVersion
    let context = try NIOSSLContext(configuration: configuration)

    return try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
        .childChannelInitializer { channel in
            channel.eventLoop.makeCompletedFuture {
                try channel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: context))
                try channel.pipeline.syncOperations.addHandler(EchoClientCertHandler())
            }
        }
        .bind(host: "127.0.0.1", port: 0)
        .get()
}

@Suite struct MTLSClientTests {
    @Test(arguments: [TLSVersionChoice.tls13, .tls12])
    func clientAuthenticatesWithCustomKey(version: TLSVersionChoice) async throws {
        let server = try await startServer()
        defer { server.close(promise: nil) }
        let port = try #require(server.localAddress?.port)

        let certificate = try TokenCertificate(keyID: Data([1]), label: "test", der: fixture("client-auth", "der"))
        let recorder = SignRecorder()
        let key = TokenPrivateKey(
            slot: 0, keyID: certificate.keyID, supported: SignatureAlgorithm.allCases,
            onSign: { algorithm, _ in recorder.record(algorithm) },
            signer: try softwareSigner()
        )

        let response = try await MTLSClient.get(
            URL(string: "https://127.0.0.1:\(port)/")!,
            certificate: certificate, privateKey: key,
            extraTrustRootsPEM: [try fixture("server", "pem")], version: version
        )

        #expect(response.statusLine == "HTTP/1.0 200 OK")
        #expect(response.body.contains("Test Client"))
        #expect(response.tlsVersion.contains(version == .tls13 ? "13" : "12"))
        // One CertificateVerify per full handshake, PSS preferred even on TLS 1.2.
        #expect(recorder.recorded == [.rsaPssRsaeSha256])
    }

    @Test func untrustedServerIsRejected() async throws {
        let server = try await startServer()
        defer { server.close(promise: nil) }
        let port = try #require(server.localAddress?.port)
        let certificate = try TokenCertificate(keyID: Data([1]), label: "test", der: fixture("client-auth", "der"))
        let key = TokenPrivateKey(slot: 0, keyID: certificate.keyID, supported: SignatureAlgorithm.allCases, signer: try softwareSigner())

        await #expect(throws: (any Error).self) {
            _ = try await MTLSClient.get(URL(string: "https://127.0.0.1:\(port)/")!, certificate: certificate, privateKey: key)
        }
    }

    @Test func connectionRefusedThrowsInsteadOfTrapping() async throws {
        // Grab a free port and close it, so nothing listens there.
        let probe = try await startServer()
        let port = try #require(probe.localAddress?.port)
        try await probe.close()

        let certificate = try TokenCertificate(keyID: Data([1]), label: "test", der: fixture("client-auth", "der"))
        let key = TokenPrivateKey(slot: 0, keyID: certificate.keyID, supported: SignatureAlgorithm.allCases, signer: try softwareSigner())
        await #expect {
            _ = try await MTLSClient.get(URL(string: "https://127.0.0.1:\(port)/")!, certificate: certificate, privateKey: key)
        } throws: { error in
            if case MTLSClientError.connectFailed = error { true } else { false }
        }
    }
}
