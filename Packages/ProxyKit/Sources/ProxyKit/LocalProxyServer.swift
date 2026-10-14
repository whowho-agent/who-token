import Foundation
import NIOCore
import NIOPosix
import NIOSSL

public enum ProxyEvent: Sendable {
    /// Passthrough: bytes are relayed without decryption.
    case tunnel(host: String, port: Int)
    /// MITM with client authentication by the token.
    case intercept(host: String, port: Int, withClientCertificate: Bool)
    case failed(host: String, port: Int, error: String)
}

/// HTTP CONNECT proxy on 127.0.0.1 for WKWebView (`WKWebsiteDataStore.proxyConfigurations`).
/// Hosts accepted by `shouldIntercept` are decrypted with a local CA and re-encrypted upstream with mTLS,
/// everything else is tunnelled untouched.
public final class LocalProxyServer: Sendable {
    public struct Configuration: Sendable {
        public var shouldIntercept: @Sendable (String) -> Bool
        public var identityProvider: any ClientIdentityProvider
        /// Extra roots for verifying intercepted servers, in addition to the system ones.
        public var extraTrustRootsPEM: [Data]
        /// `Proxy-Authorization: Basic` credentials required from clients; nil disables the check.
        public var credentials: (user: String, password: String)?
        /// Upstream TLS sessions to resume instead of signing with the token again; nil disables resumption.
        public var sessionCache: UpstreamSessionCache?
        public var onEvent: @Sendable (ProxyEvent) -> Void

        public init(
            shouldIntercept: @escaping @Sendable (String) -> Bool,
            identityProvider: any ClientIdentityProvider,
            extraTrustRootsPEM: [Data] = [],
            credentials: (user: String, password: String)? = nil,
            sessionCache: UpstreamSessionCache? = UpstreamSessionCache(),
            onEvent: @escaping @Sendable (ProxyEvent) -> Void = { _ in }
        ) {
            self.shouldIntercept = shouldIntercept
            self.identityProvider = identityProvider
            self.extraTrustRootsPEM = extraTrustRootsPEM
            self.credentials = credentials
            self.sessionCache = sessionCache
            self.onEvent = onEvent
        }
    }

    public let authority: MitmCertificateAuthority
    /// What clients must send in `Proxy-Authorization` (the client side gives them to WebKit).
    public let credentials: (user: String, password: String)?
    /// Clear it (`removeAll()`) when the user signs out of the token.
    public let sessionCache: UpstreamSessionCache?
    private let channel: Channel

    public var port: Int { channel.localAddress?.port ?? 0 }

    private init(
        authority: MitmCertificateAuthority,
        credentials: (user: String, password: String)?,
        sessionCache: UpstreamSessionCache?,
        channel: Channel
    ) {
        self.authority = authority
        self.credentials = credentials
        self.sessionCache = sessionCache
        self.channel = channel
    }

    /// Random per-launch credentials: any app on the phone can reach 127.0.0.1, only WebKit gets these.
    public static func randomCredentials() -> (user: String, password: String) {
        func random(_ count: Int) -> String {
            var generator = SystemRandomNumberGenerator()  // arc4random: cryptographically secure on Apple platforms
            let bytes = (0..<count).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
            // base64url without padding: no ':' (Basic separator) and no characters needing escaping.
            return Data(bytes).base64EncodedString()
                .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }
        return ("rb-" + random(6), random(24))
    }

    public static func start(_ configuration: Configuration, port: Int = 0) async throws -> LocalProxyServer {
        let authority = try MitmCertificateAuthority()
        let channel = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
            .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(
                        ProxyFrontHandler(configuration: configuration, authority: authority)
                    )
                }
            }
            .bind(host: "127.0.0.1", port: port)
            .get()
        return LocalProxyServer(
            authority: authority,
            credentials: configuration.credentials,
            sessionCache: configuration.sessionCache,
            channel: channel
        )
    }

    public func stop() async {
        try? await channel.close()
    }
}

/// Reads the proxy request head, connects upstream and then turns the connection into a byte relay.
final class ProxyFrontHandler: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    private let configuration: LocalProxyServer.Configuration
    private let authority: MitmCertificateAuthority
    private var head = ByteBuffer()
    private var started = false

    init(configuration: LocalProxyServer.Configuration, authority: MitmCertificateAuthority) {
        self.configuration = configuration
        self.authority = authority
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard !started else { return }
        var buffer = unwrapInboundIn(data)
        head.writeBuffer(&buffer)
        let bytes = head.readableBytesView
        guard let end = bytes.firstRange(of: Array("\r\n\r\n".utf8)) else {
            if head.readableBytes > 16 * 1024 { respond(context, "431 Request Header Fields Too Large") }
            return
        }
        started = true
        let headText = String(decoding: bytes[bytes.startIndex..<end.lowerBound], as: UTF8.self)
        let lines = headText.components(separatedBy: "\r\n")
        let parts = lines[0].split(separator: " ", maxSplits: 2).map(String.init)
        guard parts.count == 3 else { return respond(context, "400 Bad Request") }

        if let credentials = configuration.credentials,
           !Self.authorized(headerLines: lines.dropFirst(), user: credentials.user, password: credentials.password) {
            // RFC 7235: 407 + Proxy-Authenticate. The connection is closed; clients (CFNetwork) retry on a new
            // one with the credentials. Reported as an event so a client that never authenticates is visible.
            let target = Self.hostPort(parts[1], defaultPort: 443) ?? (parts[1], 0)
            let sent = lines.dropFirst().contains { $0.lowercased().hasPrefix("proxy-authorization:") }
            configuration.onEvent(.failed(host: target.0, port: target.1,
                                          error: "407 proxy authentication required (\(sent ? "wrong credentials" : "no credentials"))"))
            return respond(context, "407 Proxy Authentication Required", extra: "Proxy-Authenticate: Basic realm=\"RutokenBrowser\"\r\n")
        }

        if parts[0].uppercased() == "CONNECT" {
            guard let (host, port) = Self.hostPort(parts[1], defaultPort: 443) else { return respond(context, "400 Bad Request") }
            connect(context: context, host: host, port: port, intercept: configuration.shouldIntercept(host), forward: nil)
        } else if let url = URL(string: parts[1]), url.scheme == "http", let host = url.host() {
            // Plain HTTP in absolute form: relay the request as is (servers must accept absolute-form).
            var forward = head
            forward.moveReaderIndex(to: 0)
            connect(context: context, host: host, port: url.port ?? 80, intercept: false, forward: forward)
        } else {
            respond(context, "400 Bad Request")
        }
    }

    private func connect(context: ChannelHandlerContext, host: String, port: Int, intercept: Bool, forward: ByteBuffer?) {
        let loop = context.eventLoop
        let contextBox = NIOLoopBound(context, eventLoop: loop)
        let (frontGlue, upstreamGlue) = GlueHandler.matchedPair()
        let configuration = configuration
        let authority = authority

        let promise = loop.makePromise(of: (Channel, Bool).self)
        promise.completeWithTask {
            let identity = intercept ? try await configuration.identityProvider.identity(for: host) : nil
            let upstreamContext = intercept
                ? try UpstreamTLS.context(identity: identity, extraTrustRootsPEM: configuration.extraTrustRootsPEM)
                : nil
            let hasIdentity = identity != nil
            let serverHostname = UpstreamTLS.serverHostname(host)
            let lease = intercept
                ? await configuration.sessionCache?.checkout(.init(host: host, port: port, identity: identity))
                : nil
            let bootstrap = ClientBootstrap(group: loop)
                .connectTimeout(.seconds(15))
                .channelInitializer { channel in
                    channel.eventLoop.makeCompletedFuture {
                        if let upstreamContext {
                            try UpstreamTLS.addClientHandlers(
                                to: channel.pipeline.syncOperations, context: upstreamContext,
                                serverHostname: serverHostname, lease: lease
                            )
                        }
                        try channel.pipeline.syncOperations.addHandler(upstreamGlue)
                    }
                }
            do {
                return (try await bootstrap.connect(host: host, port: port).get(), hasIdentity)
            } catch {
                lease?.finish()
                throw error
            }
        }

        promise.futureResult.whenComplete { result in
            let context = contextBox.value
            switch result {
            case .failure(let error):
                configuration.onEvent(.failed(host: host, port: port, error: String(describing: error)))
                self.respond(context, "502 Bad Gateway")
            case .success(let (upstream, hasIdentity)):
                if let forward {
                    configuration.onEvent(.tunnel(host: host, port: port))
                    self.becomeRelay(context, glue: frontGlue, tls: nil, initial: forward)
                    return
                }
                let tls: NIOSSLServerHandler?
                if intercept {
                    do {
                        tls = NIOSSLServerHandler(context: try authority.serverContext(for: host))
                    } catch {
                        configuration.onEvent(.failed(host: host, port: port, error: String(describing: error)))
                        upstream.close(promise: nil)
                        return self.respond(context, "502 Bad Gateway")
                    }
                    configuration.onEvent(.intercept(host: host, port: port, withClientCertificate: hasIdentity))
                } else {
                    tls = nil
                    configuration.onEvent(.tunnel(host: host, port: port))
                }
                let bound = NIOLoopBound((context, tls), eventLoop: loop)
                context.writeAndFlush(self.wrapOutboundOut(ByteBuffer(string: "HTTP/1.1 200 Connection Established\r\n\r\n")))
                    .whenSuccess { self.becomeRelay(bound.value.0, glue: frontGlue, tls: bound.value.1, initial: nil) }
            }
        }
    }

    /// Replaces this handler with (optional TLS termination +) the glue towards upstream.
    private func becomeRelay(_ context: ChannelHandlerContext, glue: GlueHandler, tls: NIOSSLServerHandler?, initial: ByteBuffer?) {
        do {
            if let tls { try context.pipeline.syncOperations.addHandler(tls, position: .first) }
            try context.pipeline.syncOperations.addHandler(glue)
            context.pipeline.syncOperations.removeHandler(context: context, promise: nil)
            if let initial {
                context.pipeline.syncOperations.fireChannelRead(NIOAny(initial))
                context.pipeline.syncOperations.fireChannelReadComplete()
            }
        } catch {
            context.close(promise: nil)
        }
    }

    private func respond(_ context: ChannelHandlerContext, _ status: String, extra: String = "") {
        let response = "HTTP/1.1 \(status)\r\n\(extra)Content-Length: 0\r\nConnection: close\r\n\r\n"
        let bound = NIOLoopBound(context, eventLoop: context.eventLoop)
        context.writeAndFlush(wrapOutboundOut(ByteBuffer(string: response))).whenComplete { _ in
            bound.value.close(promise: nil)
        }
    }

    /// Checks `Proxy-Authorization: Basic …` against the expected credentials in constant time.
    static func authorized(headerLines: some Sequence<String>, user: String, password: String) -> Bool {
        let expected = Array("\(user):\(password)".utf8)
        var matched = false
        for line in headerLines {
            guard let colon = line.firstIndex(of: ":"),
                  line[..<colon].trimmingCharacters(in: .whitespaces).lowercased() == "proxy-authorization" else { continue }
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            let pieces = value.split(separator: " ", maxSplits: 1)
            guard pieces.count == 2, pieces[0].lowercased() == "basic",
                  let decoded = Data(base64Encoded: pieces[1].trimmingCharacters(in: .whitespaces)) else { continue }
            matched = constantTimeEquals(Array(decoded), expected) || matched
        }
        return matched
    }

    /// Time depends only on the lengths, not on where the bytes differ.
    static func constantTimeEquals(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        var difference: UInt8 = a.count == b.count ? 0 : 1
        for index in 0..<max(a.count, b.count) {
            difference |= (index < a.count ? a[index] : 0) ^ (index < b.count ? b[index] : 0)
        }
        return difference == 0
    }

    static func hostPort(_ authority: String, defaultPort: Int) -> (String, Int)? {
        // [v6]:port, host:port or host
        if authority.hasPrefix("["), let close = authority.firstIndex(of: "]") {
            let host = String(authority[authority.index(after: authority.startIndex)..<close])
            let portPart = authority[authority.index(after: close)...].dropFirst()
            return (host, Int(portPart) ?? defaultPort)
        }
        let pieces = authority.split(separator: ":", omittingEmptySubsequences: false)
        guard let host = pieces.first, !host.isEmpty else { return nil }
        return (String(host), pieces.count > 1 ? Int(pieces[1]) ?? defaultPort : defaultPort)
    }
}
