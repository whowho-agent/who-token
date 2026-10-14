import Foundation
import NIOCore
import NIOPosix
import Testing
@testable import ProxyKit

private struct NoIdentityProvider: ClientIdentityProvider {
    func identity(for host: String) async throws -> ClientIdentity? { nil }
}

/// Sends one CONNECT and returns everything the proxy answers until it closes the connection.
private func rawConnect(proxyPort: Int, target: String, extraHeaders: String = "") async throws -> String {
    let collector = ResponseCollector()
    let channel = try await ClientBootstrap(group: MultiThreadedEventLoopGroup.singleton)
        .channelInitializer { channel in
            channel.eventLoop.makeCompletedFuture { try channel.pipeline.syncOperations.addHandler(collector) }
        }
        .connect(host: "127.0.0.1", port: proxyPort)
        .get()
    try await channel.writeAndFlush(ByteBuffer(string: "CONNECT \(target) HTTP/1.1\r\nHost: \(target)\r\n\(extraHeaders)\r\n")).get()
    return String(decoding: try await collector.result.get(), as: UTF8.self)
}

private func basic(_ user: String, _ password: String) -> String {
    "Basic " + Data("\(user):\(password)".utf8).base64EncodedString()
}

@Suite struct ProxyAuthenticationTests {
    private func startProxy(events: EventRecorder) async throws -> (LocalProxyServer, user: String, password: String) {
        let credentials = LocalProxyServer.randomCredentials()
        let proxy = try await LocalProxyServer.start(.init(
            shouldIntercept: { _ in false },
            identityProvider: NoIdentityProvider(),
            credentials: credentials,
            onEvent: events.record
        ))
        return (proxy, credentials.user, credentials.password)
    }

    @Test func rejectsMissingCredentialsWithChallenge() async throws {
        let events = EventRecorder()
        let (proxy, _, _) = try await startProxy(events: events)
        defer { Task { await proxy.stop() } }

        let response = try await rawConnect(proxyPort: proxy.port, target: "127.0.0.1:9")

        #expect(response.hasPrefix("HTTP/1.1 407 "))
        #expect(response.contains("Proxy-Authenticate: Basic realm="))
        // The client has to retry on a new connection; this one is closed (rawConnect returned on close).
        #expect(response.contains("Connection: close"))
        #expect(events.events.contains { if case .failed(_, _, let error) = $0 { error.contains("no credentials") } else { false } })
    }

    @Test func rejectsWrongCredentials() async throws {
        let events = EventRecorder()
        let (proxy, user, password) = try await startProxy(events: events)
        defer { Task { await proxy.stop() } }

        for header in [basic(user, password + "x"), basic(user, String(password.dropLast())), basic("other", password),
                       "Bearer \(password)", "Basic not-base64!"] {
            let response = try await rawConnect(
                proxyPort: proxy.port, target: "127.0.0.1:9", extraHeaders: "Proxy-Authorization: \(header)\r\n"
            )
            #expect(response.hasPrefix("HTTP/1.1 407 "), "header: \(header)")
        }
        #expect(events.events.allSatisfy { if case .failed(_, _, let error) = $0 { error.contains("wrong credentials") } else { false } })
    }

    @Test func tunnelsWithCorrectCredentials() async throws {
        let server = try await startServer(requireClientCertificate: false)
        defer { server.close(promise: nil) }
        let serverPort = try #require(server.localAddress?.port)
        let events = EventRecorder()
        let (proxy, user, password) = try await startProxy(events: events)
        defer { Task { await proxy.stop() } }
        #expect(proxy.credentials?.user == user)

        let pem = String(decoding: try fixture("server", "pem"), as: UTF8.self)
            .components(separatedBy: "\n").filter { !$0.hasPrefix("-----") }.joined()
        let response = try await ProxyClient.get(
            host: "127.0.0.1", port: serverPort, proxyPort: proxy.port,
            trustRootsDER: [try #require(Data(base64Encoded: pem))], proxyAuthorization: basic(user, password)
        )

        #expect(response.hasPrefix("HTTP/1.0 200"))
        #expect(events.events.contains { if case .tunnel = $0 { true } else { false } })
    }

    @Test func comparesCredentialsExactly() {
        let lines = ["Host: x", "proxy-authorization:  basic \(Data("u:p".utf8).base64EncodedString())"]
        #expect(ProxyFrontHandler.authorized(headerLines: lines, user: "u", password: "p"))
        #expect(!ProxyFrontHandler.authorized(headerLines: lines, user: "u", password: "pp"))
        #expect(!ProxyFrontHandler.authorized(headerLines: ["Host: x"], user: "u", password: "p"))
        #expect(ProxyFrontHandler.constantTimeEquals([1, 2, 3], [1, 2, 3]))
        #expect(!ProxyFrontHandler.constantTimeEquals([1, 2, 3], [1, 2]))
        #expect(!ProxyFrontHandler.constantTimeEquals([], [0]))
        #expect(!ProxyFrontHandler.constantTimeEquals([1, 2, 3], [1, 2, 4]))
    }

    @Test func randomCredentialsAreUniqueAndHeaderSafe() {
        let a = LocalProxyServer.randomCredentials(), b = LocalProxyServer.randomCredentials()
        #expect(a.password != b.password)
        #expect(a.password.count >= 32)
        #expect(!(a.user + a.password).contains { ":+/= \r\n".contains($0) })
    }
}
