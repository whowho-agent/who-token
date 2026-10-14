import Security
import SwiftUI
import WebKit

/// Plain WKWebView (no proxy): the client certificate comes from the system keychain,
/// where the CryptoTokenKit extension exposes the token's identity.
struct WebTestView: View {
    let url: URL
    let trustedRootsPEM: [Data]
    let log: (String) -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            WebView(url: url, trustedRootsPEM: trustedRootsPEM, log: log)
                .ignoresSafeArea(edges: .bottom)
                .navigationTitle(url.host() ?? "")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .confirmationAction) { Button("Готово") { dismiss() } }
                }
        }
    }
}

private struct WebView: UIViewRepresentable {
    let url: URL
    let trustedRootsPEM: [Data]
    let log: (String) -> Void

    func makeCoordinator() -> Coordinator { Coordinator(anchors: trustedRootsPEM.compactMap(Self.certificate(pem:)), log: log) }

    func makeUIView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .nonPersistent()
        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = context.coordinator
        webView.load(URLRequest(url: url))
        return webView
    }

    func updateUIView(_ webView: WKWebView, context: Context) {}

    private static func certificate(pem: Data) -> SecCertificate? {
        let base64 = String(decoding: pem, as: UTF8.self)
            .components(separatedBy: "\n")
            .filter { !$0.hasPrefix("-----") }
            .joined()
        return Data(base64Encoded: base64).flatMap { SecCertificateCreateWithData(nil, $0 as CFData) }
    }

    @MainActor
    final class Coordinator: NSObject, WKNavigationDelegate {
        private let anchors: [SecCertificate]
        private let log: (String) -> Void

        init(anchors: [SecCertificate], log: @escaping (String) -> Void) {
            self.anchors = anchors
            self.log = log
        }

        func webView(_ webView: WKWebView, respondTo challenge: URLAuthenticationChallenge) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
            let space = challenge.protectionSpace
            switch space.authenticationMethod {
            case NSURLAuthenticationMethodServerTrust:
                guard let trust = space.serverTrust else { return (.performDefaultHandling, nil) }
                // Test stand: its CA is trusted in addition to the system roots.
                SecTrustSetAnchorCertificates(trust, anchors as CFArray)
                SecTrustSetAnchorCertificatesOnly(trust, false)
                var error: CFError?
                guard SecTrustEvaluateWithError(trust, &error) else {
                    log("WebView: сервер \(space.host) не прошёл проверку: \(error.map { String(describing: $0) } ?? "")")
                    return (.cancelAuthenticationChallenge, nil)
                }
                return (.useCredential, URLCredential(trust: trust))

            case NSURLAuthenticationMethodClientCertificate:
                let identities = SystemTokenRegistry.identities()
                log("WebView: \(space.host) запросил сертификат, системных удостоверений с токена: \(identities.count)")
                guard let identity = identities.first else { return (.performDefaultHandling, nil) }
                return (.useCredential, URLCredential(identity: identity, certificates: nil, persistence: .forSession))

            default:
                return (.performDefaultHandling, nil)
            }
        }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            log("WebView: страница загружена")
        }

        func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
            log("WebView: ошибка загрузки: \(error.localizedDescription)")
        }
    }
}
