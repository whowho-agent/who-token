import Network
import Security
import SwiftUI
import WebKit

struct BrowserView: View {
    @Bindable var model: BrowserModel
    @State private var page = PageState()
    @State private var showSettings = false

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Image(systemName: page.isIntercepted ? "lock.shield.fill" : "lock")
                    .foregroundStyle(page.isIntercepted ? .green : .secondary)
                TextField("Адрес", text: $model.address)
                    .keyboardType(.URL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .submitLabel(.go)
                    .onSubmit { model.go() }
            }
            .padding(10)
            .background(.bar)
            ProgressView(value: page.progress)
                .opacity(page.progress < 1 ? 1 : 0)

            if let port = model.proxyPort, let proxy = model.proxy {
                ZStack {
                    WebView(model: model, page: page, proxyPort: port, proxyCA: proxy.authority.caCertificateDER)
                    // Overlays keep the web view alive underneath, with its history and popups.
                    if let failure = page.failure, let error = model.browserError(for: failure) {
                        ErrorPageView(error: error, host: failure.url.host() ?? "", retry: retry) { showSettings = true }
                    } else if !page.hasStarted && model.address.isEmpty {
                        BrowserEmptyState { showSettings = true }
                    }
                }
            } else {
                ContentUnavailableView(model.status, systemImage: "network.slash")
            }
        }
        .toolbar {
            ToolbarItemGroup(placement: .bottomBar) {
                Button("Назад", systemImage: "chevron.backward") { page.webView?.goBack() }.disabled(!page.canGoBack)
                Button("Вперёд", systemImage: "chevron.forward") { page.webView?.goForward() }.disabled(!page.canGoForward)
                Spacer()
                Button("Обновить", systemImage: "arrow.clockwise", action: retry)
                Button(model.desktopMode ? "Мобильная версия" : "Версия для компьютера",
                       systemImage: model.desktopMode ? "desktopcomputer.trianglebadge.exclamationmark" : "desktopcomputer") {
                    model.desktopMode.toggle()
                }
                .tint(model.desktopMode ? .accentColor : .secondary)
                Button("Настройки", systemImage: "gearshape") { showSettings = true }
            }
        }
        // Applies both the toolbar button and the settings toggle.
        .onChange(of: model.desktopMode) {
            page.webView?.customUserAgent = model.desktopMode ? desktopUserAgent() : nil
            page.webView?.reload()
        }
        .sheet(isPresented: $showSettings) { SettingsView(model: model) }
        .sheet(item: $page.popup) { popup in
            NavigationStack {
                PopupView(webView: popup.webView)
                    .ignoresSafeArea(edges: .bottom)
                    .navigationTitle(popup.webView.url?.host() ?? "")
                    .navigationBarTitleDisplayMode(.inline)
                    .toolbar {
                        ToolbarItem(placement: .cancellationAction) { Button("Закрыть") { page.popup = nil } }
                    }
            }
        }
        .task { await model.start() }
    }

    /// After a failed provisional navigation `reload()` would reload the previous page, so load the failed URL.
    private func retry() {
        if let failure = page.failure {
            page.failure = nil
            page.webView?.load(URLRequest(url: failure.url))
        } else {
            page.webView?.reload()
        }
    }
}

@MainActor @Observable
final class PageState {
    weak var webView: WKWebView?
    var progress = 0.0
    var canGoBack = false
    var canGoForward = false
    var isIntercepted = false
    /// Any main-frame navigation has started; until then an empty address shows the first-launch hint.
    var hasStarted = false
    /// The last main-frame navigation failed; shown as a native error page.
    var failure: NavigationFailure?
    /// Window opened by `window.open` (e.g. SAML sign-in); it must stay linked to its opener.
    var popup: Popup?
}

struct Popup: Identifiable {
    let id = UUID()
    let webView: WKWebView
}

private struct PopupView: UIViewRepresentable {
    let webView: WKWebView
    func makeUIView(context: Context) -> WKWebView { webView }
    func updateUIView(_ webView: WKWebView, context: Context) {}
}

private struct WebView: UIViewRepresentable {
    let model: BrowserModel
    let page: PageState
    let proxyPort: Int
    let proxyCA: Data

    func makeCoordinator() -> Coordinator { Coordinator(model: model, page: page, proxyCA: proxyCA) }

    func makeUIView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        // Persistent store (sign-ins survive restarts). The proxy port changes every launch,
        // so the proxy is set on it here each time, before the first load.
        let store = model.dataStore
        // All WebKit traffic goes through the in-app proxy (iOS 17+).
        store.proxyConfigurations = [ProxyConfiguration(
            httpCONNECTProxy: .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(integerLiteral: UInt16(proxyPort)))
        )]
        configuration.websiteDataStore = store
        configuration.preferences.javaScriptCanOpenWindowsAutomatically = true
        // WKWebView's default user agent lacks "Version/… Safari/…", so sites sniffing for Safari
        // (e.g. apps choosing a modern or legacy JS bundle by user agent) serve a degraded or broken page.
        configuration.applicationNameForUserAgent = safariApplicationName()
        // Diagnostics: forward JS errors and console warnings/errors to the app log.
        configuration.userContentController.add(context.coordinator, name: "diag")
        configuration.userContentController.addUserScript(WKUserScript(source: """
            (function() {
              const send = (kind, args) => { try { window.webkit.messageHandlers.diag.postMessage(kind + ': ' + Array.from(args).map(String).join(' ').slice(0, 500)); } catch (e) {} };
              const origError = console.error, origWarn = console.warn;
              console.error = function() { send('console.error', arguments); origError.apply(console, arguments); };
              console.warn = function() { send('console.warn', arguments); origWarn.apply(console, arguments); };
              window.addEventListener('error', e => send('error', [e.message, e.filename + ':' + e.lineno]));
              window.addEventListener('unhandledrejection', e => send('unhandledrejection', [e.reason]));
              const origOpen = window.open;
              window.open = function() { send('window.open', arguments); return origOpen.apply(window, arguments); };
            })();
            """, injectionTime: .atDocumentStart, forMainFrameOnly: false))
        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.navigationDelegate = context.coordinator
        webView.uiDelegate = context.coordinator
        webView.customUserAgent = model.desktopMode ? desktopUserAgent() : nil
        context.coordinator.observe(webView)
        page.webView = webView
        return webView
    }

    func updateUIView(_ webView: WKWebView, context: Context) {
        if let url = model.loadRequest {
            model.loadRequest = nil
            webView.load(URLRequest(url: url))
        }
    }

    @MainActor
    final class Coordinator: NSObject, WKNavigationDelegate, WKUIDelegate, WKScriptMessageHandler {
        private let model: BrowserModel
        private let page: PageState
        private let proxyCA: SecCertificate?
        private var observations: [NSKeyValueObservation] = []

        init(model: BrowserModel, page: PageState, proxyCA: Data) {
            self.model = model
            self.page = page
            self.proxyCA = SecCertificateCreateWithData(nil, proxyCA as CFData)
        }

        func observe(_ webView: WKWebView) {
            observations = [
                webView.observe(\.estimatedProgress) { [weak self] view, _ in MainActor.assumeIsolated { self?.page.progress = view.estimatedProgress } },
                webView.observe(\.canGoBack) { [weak self] view, _ in MainActor.assumeIsolated { self?.page.canGoBack = view.canGoBack } },
                webView.observe(\.canGoForward) { [weak self] view, _ in MainActor.assumeIsolated { self?.page.canGoForward = view.canGoForward } },
                webView.observe(\.url) { [weak self] view, _ in
                    MainActor.assumeIsolated {
                        guard let self, let url = view.url else { return }
                        self.model.address = url.absoluteString
                        self.page.isIntercepted = url.host().map(self.model.isIntercepted) ?? false
                    }
                }
            ]
        }

        func webView(_ webView: WKWebView, respondTo challenge: URLAuthenticationChallenge) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
            let space = challenge.protectionSpace
            switch space.authenticationMethod {
            case NSURLAuthenticationMethodServerTrust:
                // Intercepted hosts present the proxy's certificate: trust only the in-memory proxy CA.
                // The real server was already verified by the proxy.
                guard model.isIntercepted(space.host) else { return (.performDefaultHandling, nil) }
                guard let trust = space.serverTrust, let proxyCA else { return (.cancelAuthenticationChallenge, nil) }
                SecTrustSetAnchorCertificates(trust, [proxyCA] as CFArray)
                SecTrustSetAnchorCertificatesOnly(trust, true)
                let accepted = SecTrustEvaluateWithError(trust, nil)
                model.noteTrustChallenge(host: space.host, accepted: accepted)
                return accepted ? (.useCredential, URLCredential(trust: trust)) : (.cancelAuthenticationChallenge, nil)

            case NSURLAuthenticationMethodClientCertificate:
                model.log("WebView: \(space.host) запросил сертификат напрямую — хост не в списке токена")
                return (.performDefaultHandling, nil)

            default:
                return (.performDefaultHandling, nil)
            }
        }

        // MARK: WKUIDelegate

        /// `window.open`: the new view must use WebKit's configuration so `window.opener` keeps working
        /// (popup-based SAML logins report back to the opener and then close themselves).
        func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                     for navigationAction: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
            let popup = WKWebView(frame: .zero, configuration: configuration)
            popup.navigationDelegate = self
            popup.uiDelegate = self
            model.log("всплывающее окно: \(navigationAction.request.url?.absoluteString ?? "")")
            page.popup = Popup(webView: popup)
            return popup
        }

        func webViewDidClose(_ webView: WKWebView) {
            if page.popup?.webView === webView {
                model.log("всплывающее окно закрыто")
                page.popup = nil
            }
        }

        func webView(_ webView: WKWebView, runJavaScriptAlertPanelWithMessage message: String,
                     initiatedByFrame frame: WKFrameInfo) async {
            model.log("alert: \(message)")
        }

        // MARK: Diagnostics

        func userContentController(_ controller: WKUserContentController, didReceive message: WKScriptMessage) {
            model.log("js \(message.frameInfo.request.url?.host() ?? "?") \(message.body)")
        }

        // MARK: WKNavigationDelegate

        func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                     preferences: WKWebpagePreferences) async -> (WKNavigationActionPolicy, WKWebpagePreferences) {
            // Like Safari's "Request Desktop Website": desktop layout and a Mac user agent.
            preferences.preferredContentMode = model.desktopMode ? .desktop : .mobile
            webView.customUserAgent = model.desktopMode ? desktopUserAgent() : nil
            return (decidePolicy(for: navigationAction), preferences)
        }

        private func decidePolicy(for navigationAction: WKNavigationAction) -> WKNavigationActionPolicy {
            let url = navigationAction.request.url
            let frame = navigationAction.targetFrame.map { $0.isMainFrame ? "main" : "frame" } ?? "new window"
            model.log("переход [\(frame)] \(navigationAction.request.httpMethod ?? "GET") \(url?.absoluteString.prefix(200) ?? "")")
            if let scheme = url?.scheme, !["http", "https", "about", "blob", "data"].contains(scheme) {
                model.log("схема \(scheme) не поддерживается WebView, переход отменён")
                return .cancel
            }
            return .allow
        }

        func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation!) {
            guard webView === page.webView else { return }
            page.hasStarted = true
            page.failure = nil
        }

        func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
            model.log("страница загружена: \(webView.url?.absoluteString ?? "")")
            guard webView === page.webView else { return }
            page.failure = nil
            if let host = webView.url?.host() { model.navigationSucceeded(host: host) }
        }

        func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
            model.log("ошибка загрузки: \(error.localizedDescription)")
            showFailure(error, in: webView)
        }

        func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
            model.log("ошибка: \(error.localizedDescription)")
            showFailure(error, in: webView)
        }

        /// Main window only: a popup failing must not cover the opener's page.
        private func showFailure(_ error: Error, in webView: WKWebView) {
            let error = error as NSError
            guard webView === page.webView, !BrowserError.isCancellation(error),
                  let url = (error.userInfo[NSURLErrorFailingURLErrorKey] as? URL) ?? webView.url else { return }
            page.failure = NavigationFailure(url: url, error: error, date: .now)
            // WebKit keeps the previous page's URL in the address bar; show the one that failed.
            model.address = url.absoluteString
        }
    }
}

@MainActor
private func safariApplicationName() -> String {
    let version = UIDevice.current.systemVersion.split(separator: ".").prefix(2).joined(separator: ".")
    return "Version/\(version) Mobile/15E148 Safari/604.1"
}

@MainActor
private func desktopUserAgent() -> String {
    let version = UIDevice.current.systemVersion.split(separator: ".").prefix(2).joined(separator: ".")
    return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/\(version) Safari/605.1.15"
}
