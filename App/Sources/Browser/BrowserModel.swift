import Foundation
import Network
import Observation
import os
import ProxyKit
import TokenKit
import WebKit

/// Browser state: the local proxy, the list of hosts that need the token, and diagnostics.
@MainActor @Observable
final class BrowserModel {
    var address = UserDefaults.standard.string(forKey: "browserAddress") ?? "" {
        didSet { UserDefaults.standard.set(address, forKey: "browserAddress") }
    }
    /// Comma-separated hosts whose traffic goes through the token (mTLS); the rest is tunnelled.
    var tokenHosts = UserDefaults.standard.string(forKey: "tokenHosts") ?? "" {
        didSet {
            UserDefaults.standard.set(tokenHosts, forKey: "tokenHosts")
            let parsed = Self.parse(tokenHosts)
            interceptHosts.withLock { $0 = parsed }
        }
    }
    /// Desktop layout and Mac user agent, for sites that redirect iPhones to a reduced mobile UI.
    var desktopMode = UserDefaults.standard.bool(forKey: "desktopMode") {
        didSet { UserDefaults.standard.set(desktopMode, forKey: "desktopMode") }
    }
    private(set) var proxyPort: Int?
    private(set) var status = "Прокси не запущен"
    private(set) var events: [String] = []
    private(set) var trustChallenges: [String: Int] = [:]
    var loadRequest: URL?

    private(set) var proxy: LocalProxyServer?
    private(set) var identityProvider: TokenIdentityProvider?
    /// Latest token-related problem per host, for error pages.
    private(set) var identityIssues: [String: IdentityStatus] = [:]
    private let interceptHosts: OSAllocatedUnfairLock<Set<String>>
    private let service: TokenService?
    private let prompter: PinPrompter

    init(service: TokenService?, prompter: PinPrompter) {
        self.service = service
        self.prompter = prompter
        interceptHosts = OSAllocatedUnfairLock(initialState: Self.parse(UserDefaults.standard.string(forKey: "tokenHosts") ?? ""))
    }

    func start() async {
        guard proxy == nil, let service else { return }
        let hosts = interceptHosts
        let identityProvider = TokenIdentityProvider(service: service, prompter: prompter) { [weak self] status in
            Task { @MainActor in self?.record(status) }
        }
        self.identityProvider = identityProvider
        // Other apps can reach 127.0.0.1 too, so the proxy wants per-launch credentials that only WebKit
        // gets (ProxyConfiguration.applyCredential). Fallback if WebKit fails to authenticate on some
        // iOS version (every connection logged as "407 ... no credentials"): pass `credentials: nil`.
        let credentials = LocalProxyServer.randomCredentials()
        do {
            let proxy = try await LocalProxyServer.start(.init(
                shouldIntercept: { host in hosts.withLock { Self.matches(host, $0) } },
                identityProvider: identityProvider,
                extraTrustRootsPEM: Self.standCA + Self.bundledTrustRoots,
                credentials: credentials,
                onEvent: { [weak self] event in
                    Task { @MainActor in self?.record(event) }
                }
            ))
            self.proxy = proxy
            proxyPort = proxy.port
            status = "Прокси 127.0.0.1:\(proxy.port)"
            AppLog.write("[browser] прокси запущен на порту \(proxy.port), сайты с токеном: \(tokenHosts)")
            AppLog.write("[browser] прокси требует Proxy-Authorization (Basic, пароль на запуск); отказ виден как «407» в событиях")
            go()
        } catch {
            status = "Прокси не запустился: \(error)"
        }
    }

    func go() {
        var text = address.trimmingCharacters(in: .whitespaces)
        guard !text.isEmpty else { return }
        if !text.contains("://") { text = "https://" + text }
        guard let url = URL(string: text) else { return }
        address = text
        loadRequest = url
    }

    func isIntercepted(_ host: String) -> Bool {
        interceptHosts.withLock { Self.matches(host, $0) }
    }

    /// Exact host or `*.domain` pattern (matches subdomains, not the domain itself).
    nonisolated static func matches(_ host: String, _ patterns: Set<String>) -> Bool {
        let host = host.lowercased()
        return patterns.contains { pattern in
            pattern.hasPrefix("*.") ? host.hasSuffix(pattern.dropFirst()) : host == pattern
        }
    }

    /// WebView reports server-trust challenges; the spike checks they arrive for every subresource connection.
    func noteTrustChallenge(host: String, accepted: Bool) {
        trustChallenges[host, default: 0] += 1
        log("WebView: проверка сервера \(host) \(accepted ? "принята" : "ОТКЛОНЕНА") (#\(trustChallenges[host]!))")
    }

    func log(_ text: String) {
        events.insert("\(Date().formatted(.dateTime.hour().minute().second())) \(text)", at: 0)
        if events.count > 200 { events.removeLast() }
        AppLog.write("[browser] \(text)")
    }

    private func record(_ status: IdentityStatus) {
        switch status {
        case .tokenMissing(let host), .noCertificate(let host), .pinCancelled(let host):
            identityIssues[host] = status
        case .loginFailed(let host, _):
            identityIssues[host] = status
        case .signedIn:
            identityIssues.removeAll()
        }
    }

    private func record(_ event: ProxyEvent) {
        switch event {
        case .tunnel(let host, let port): log("туннель \(host):\(port)")
        case .intercept(let host, let port, let withCertificate):
            log("перехват \(host):\(port), клиентский сертификат: \(withCertificate ? "токен" : "нет")")
        case .failed(let host, let port, let error): log("ошибка \(host):\(port): \(error)")
        }
    }

    private nonisolated static func parse(_ text: String) -> Set<String> {
        Set(text.split(whereSeparator: { $0 == "," || $0 == " " }).map { $0.lowercased() })
    }

    /// Organization roots for verifying intercepted servers (App/TrustRoots/*.pem, kept out of git).
    private static let bundledTrustRoots: [Data] = (Bundle.main.urls(forResourcesWithExtension: "pem", subdirectory: "TrustRoots") ?? [])
        .compactMap { try? Data(contentsOf: $0) }

    /// CA of the local test stand (stand/run-stand.sh copies it into the app bundle).
    private static let standCA: [Data] = Bundle.main.url(forResource: "stand-ca", withExtension: "pem")
        .flatMap { try? Data(contentsOf: $0) }
        .map { [$0] } ?? []
}
