// standserver: HTTPS test stand that requires a client certificate (mTLS), with HTTP/1.1 keep-alive.
//   standserver --port 8443 --cert server.pem --key server.key --client-ca chain.pem --root www
// Serves static files from --root and /whoami (client certificate and TLS version as JSON).
// Logs every TLS handshake, so the number of token signatures per page load is visible.
import Foundation
import NIOCore
import NIOHTTP1
import NIOPosix
import NIOSSL
import NIOTLS

let arguments = CommandLine.arguments
func option(_ name: String) -> String? {
    arguments.firstIndex(of: name).flatMap { $0 + 1 < arguments.count ? arguments[$0 + 1] : nil }
}
guard let certPath = option("--cert"), let keyPath = option("--key"), let clientCAPath = option("--client-ca"),
      let root = option("--root") else {
    print("usage: standserver --port 8443 --cert server.pem --key server.key --client-ca chain.pem --root www")
    exit(2)
}
let port = Int(option("--port") ?? "8443") ?? 8443

func log(_ text: String) {
    print("\(Date().formatted(date: .omitted, time: .standard)) \(text)")
    fflush(stdout)
}

var tls = TLSConfiguration.makeServerConfiguration(
    certificateChain: try NIOSSLCertificate.fromPEMFile(certPath).map { .certificate($0) },
    privateKey: .privateKey(try NIOSSLPrivateKey(file: keyPath, format: .pem))
)
// Both the intermediate and the root are anchors, so a client sending only its leaf is accepted.
tls.trustRoots = .certificates(try NIOSSLCertificate.fromPEMFile(clientCAPath))
tls.certificateVerification = .noHostnameVerification
tls.applicationProtocols = ["http/1.1"]
let sslContext = try NIOSSLContext(configuration: tls)

final class TLSLogger: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = NIOAny
    private var peer = "?"
    private(set) var summary = "{}"

    func channelActive(context: ChannelHandlerContext) {
        peer = context.remoteAddress?.ipAddress ?? "?"
        context.fireChannelActive()
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if case TLSUserEvent.handshakeCompleted = event,
           let handler = try? context.pipeline.syncOperations.handler(type: NIOSSLServerHandler.self) {
            let version = handler.tlsVersion.map { "\($0)" } ?? "?"
            let subject = handler.peerCertificate.map { "\($0)" } ?? "нет"
            summary = "{\"tls\": \"\(version)\", \"client\": \"\(subject.replacingOccurrences(of: "\"", with: "'"))\"}"
            log("TLS handshake from \(peer): \(version), client certificate \(subject)")
        }
        context.fireUserInboundEventTriggered(event)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        log("connection from \(peer) failed: \(error)")
        context.close(promise: nil)
    }
}

final class FileServer: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTPServerRequestPart
    typealias OutboundOut = HTTPServerResponsePart

    private let root: URL
    private let tlsInfo: TLSLogger
    private var request: HTTPRequestHead?

    init(root: URL, tlsInfo: TLSLogger) {
        self.root = root
        self.tlsInfo = tlsInfo
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        switch unwrapInboundIn(data) {
        case .head(let head): request = head
        case .body: break
        case .end:
            guard let head = request else { return }
            respond(context, head)
        }
    }

    private func respond(_ context: ChannelHandlerContext, _ head: HTTPRequestHead) {
        let path = head.uri.split(separator: "?").first.map(String.init) ?? "/"
        var body: Data
        var type = "text/plain; charset=utf-8"
        var status = HTTPResponseStatus.ok
        if path == "/whoami" {
            body = Data(tlsInfo.summary.utf8)
            type = "application/json"
        } else {
            let file = root.appending(path: path == "/" ? "index.html" : String(path.dropFirst())).standardized
            if file.path.hasPrefix(root.standardized.path), let data = try? Data(contentsOf: file) {
                body = data
                type = Self.contentTypes[file.pathExtension] ?? "application/octet-stream"
            } else {
                body = Data("not found".utf8)
                status = .notFound
            }
        }
        log("\(head.method) \(head.uri) -> \(status.code)")
        var headers = HTTPHeaders([("Content-Type", type), ("Content-Length", "\(body.count)"), ("Cache-Control", "no-store")])
        if !head.isKeepAlive { headers.add(name: "Connection", value: "close") }
        context.write(wrapOutboundOut(.head(HTTPResponseHead(version: head.version, status: status, headers: headers))), promise: nil)
        context.write(wrapOutboundOut(.body(.byteBuffer(ByteBuffer(bytes: body)))), promise: nil)
        let keepAlive = head.isKeepAlive
        let bound = NIOLoopBound(context, eventLoop: context.eventLoop)
        context.writeAndFlush(wrapOutboundOut(.end(nil))).whenComplete { _ in
            if !keepAlive { bound.value.close(promise: nil) }
        }
    }

    static let contentTypes = [
        "html": "text/html; charset=utf-8", "css": "text/css", "js": "text/javascript",
        "json": "application/json", "png": "image/png", "svg": "image/svg+xml"
    ]
}

let rootURL = URL(fileURLWithPath: root)
let server = try await ServerBootstrap(group: MultiThreadedEventLoopGroup.singleton)
    .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
    .childChannelInitializer { channel in
        channel.eventLoop.makeCompletedFuture {
            let tlsLogger = TLSLogger()
            try channel.pipeline.syncOperations.addHandler(NIOSSLServerHandler(context: sslContext))
            try channel.pipeline.syncOperations.addHandler(tlsLogger)
            try channel.pipeline.syncOperations.configureHTTPServerPipeline()
            try channel.pipeline.syncOperations.addHandler(FileServer(root: rootURL, tlsInfo: tlsLogger))
        }
    }
    .bind(host: "::", port: port)
    .get()
log("standserver listening on port \(port), files from \(rootURL.path)")
try await server.closeFuture.get()
