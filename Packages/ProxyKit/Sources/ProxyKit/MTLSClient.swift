import Foundation
import NIOCore
import NIOPosix
import NIOSSL
import NIOTLS
import TokenKit

public enum TLSVersionChoice: String, CaseIterable, Sendable {
    case automatic = "TLS 1.2–1.3"
    case tls12 = "TLS 1.2"
    case tls13 = "TLS 1.3"
}

public struct MTLSResponse: Sendable {
    public let statusLine: String
    public let body: String
    public let tlsVersion: String
    public let elapsed: Duration
}

public enum MTLSClientError: Error, CustomStringConvertible {
    case invalidURL
    case emptyResponse
    case connectFailed(host: String, port: Int, reason: String)

    public var description: String {
        switch self {
        case .invalidURL: "Некорректный адрес (нужен https://host[:port]/path)"
        case .emptyResponse: "Сервер закрыл соединение без ответа"
        case .connectFailed(let host, let port, let reason):
            "Не удалось подключиться к \(host):\(port): \(reason). "
                + "Проверьте, что сервер запущен, разрешён доступ к локальной сети "
                + "(Настройки → Конфиденциальность → Локальная сеть) и брандмауэр Mac пропускает соединение"
        }
    }
}

/// Stage 2 spike: one HTTPS GET with client authentication by a token key.
/// HTTP is written and read raw (Connection: close): the proxy will relay bytes the same way.
public enum MTLSClient {
    public static func get(
        _ url: URL,
        certificate: TokenCertificate,
        privateKey: TokenPrivateKey,
        extraTrustRootsPEM: [Data] = [],
        version: TLSVersionChoice = .automatic,
        sessionCache: UpstreamSessionCache? = nil
    ) async throws -> MTLSResponse {
        guard url.scheme == "https", let host = url.host() else { throw MTLSClientError.invalidURL }
        let port = url.port ?? 443
        let path = url.path().isEmpty ? "/" : url.path() + (url.query().map { "?\($0)" } ?? "")

        let identity = ClientIdentity(certificate: certificate, privateKey: privateKey)
        let context = try UpstreamTLS.context(
            identity: identity,
            extraTrustRootsPEM: extraTrustRootsPEM,
            version: version
        )
        let serverHostname = UpstreamTLS.serverHostname(host)

        let start = ContinuousClock.now
        let lease = await sessionCache?.checkout(.init(host: host, port: port, identity: identity))
        let collector = ResponseCollector()
        let channel: Channel
        do {
            channel = try await ClientBootstrap(group: MultiThreadedEventLoopGroup.singleton)
                .connectTimeout(.seconds(15))
                .channelInitializer { channel in
                    channel.eventLoop.makeCompletedFuture {
                        try UpstreamTLS.addClientHandlers(
                            to: channel.pipeline.syncOperations, context: context,
                            serverHostname: serverHostname, lease: lease
                        )
                        try channel.pipeline.syncOperations.addHandler(collector)
                    }
                }
                .connect(host: host, port: port)
                .get()
        } catch {
            lease?.finish()
            throw MTLSClientError.connectFailed(host: host, port: port, reason: String(describing: error))
        }

        let request = "GET \(path) HTTP/1.1\r\nHost: \(url.host(percentEncoded: true) ?? host)\r\nUser-Agent: RutokenBrowser-mtls\r\nConnection: close\r\n\r\n"
        do {
            try await channel.writeAndFlush(ByteBuffer(string: request)).get()
        } catch {
            // A failed handshake closes the channel; report the TLS error rather than the failed write.
            _ = try await collector.result.get()
            throw error
        }
        let raw = try await collector.result.get()
        try? await channel.close().get()

        guard !raw.isEmpty else { throw MTLSClientError.emptyResponse }
        let text = String(decoding: raw, as: UTF8.self)
        let parts = text.components(separatedBy: "\r\n\r\n")
        return MTLSResponse(
            statusLine: text.components(separatedBy: "\r\n").first ?? "",
            body: parts.dropFirst().joined(separator: "\r\n\r\n"),
            tlsVersion: collector.tlsVersion ?? "?",
            elapsed: ContinuousClock.now - start
        )
    }
}

/// Collects the whole response until the server closes the connection.
final class ResponseCollector: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer

    private var buffer: [UInt8] = []
    /// Read when the handshake completes: the server may close the channel right after responding.
    private(set) var tlsVersion: String?
    private var promise: EventLoopPromise<[UInt8]>?
    private var pending: EventLoopFuture<[UInt8]>?

    var result: EventLoopFuture<[UInt8]> { pending! }

    func handlerAdded(context: ChannelHandlerContext) {
        let promise = context.eventLoop.makePromise(of: [UInt8].self)
        self.promise = promise
        pending = promise.futureResult
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if case TLSUserEvent.handshakeCompleted = event,
           let tls = try? context.pipeline.syncOperations.handler(type: NIOSSLClientHandler.self) {
            tlsVersion = tls.tlsVersion.map(String.init(describing:))
        }
        context.fireUserInboundEventTriggered(event)
    }

    /// The channel may close without ever becoming active (e.g. connection refused or no local network
    /// permission); NIO traps on a promise left unfulfilled, so fail it here.
    func handlerRemoved(context: ChannelHandlerContext) {
        promise?.fail(ChannelError.ioOnClosedChannel)
        promise = nil
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        buffer += Array(unwrapInboundIn(data).readableBytesView)
    }

    func channelInactive(context: ChannelHandlerContext) {
        promise?.succeed(buffer)
        promise = nil
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        // Servers often close without close_notify after a complete HTTP/1.0 response.
        if case NIOSSLError.uncleanShutdown = error, !buffer.isEmpty {
            promise?.succeed(buffer)
        } else {
            promise?.fail(error)
        }
        promise = nil
        context.close(promise: nil)
    }
}

extension String {
    var isIPAddress: Bool {
        var v4 = in_addr(), v6 = in6_addr()
        return inet_pton(AF_INET, self, &v4) == 1 || inet_pton(AF_INET6, self, &v6) == 1
    }
}
