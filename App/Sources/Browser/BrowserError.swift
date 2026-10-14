import Foundation

/// Readable error page for a failed main-frame navigation.
///
/// WebKit only sees the local proxy, so a token or upstream TLS problem reaches it as a vague
/// "network connection lost". The real cause comes from the token (`IdentityStatus`) and the proxy
/// (`ProxyEvent.failed`); this type turns them into Russian text. Pure, so it is unit-tested without WebKit.
struct BrowserError: Equatable, Sendable {
    enum Kind: Equatable, Sendable {
        case tokenMissing
        case noCertificate
        case pinCancelled
        case pinLocked
        case tokenLoginFailed
        /// The server rejected the certificate from the token (TLS alert from the server).
        case clientCertificateRejected
        /// A site outside the token list asked WebKit for a client certificate.
        case clientCertificateRequested
        case serverCertificateUntrusted
        case serverNameMismatch
        case secureConnectionFailed
        case connectionLost
        case hostNotFound
        case serverUnreachable
        case offline
        case timedOut
        case generic
    }

    let kind: Kind
    let title: String
    let message: String
    /// What the user can do besides «Повторить».
    let hint: String?
    /// Raw error texts for the «Подробности» disclosure.
    let details: String?

    var systemImage: String {
        switch kind {
        case .tokenMissing, .noCertificate, .pinCancelled, .pinLocked, .tokenLoginFailed: "key.slash"
        case .clientCertificateRejected, .clientCertificateRequested: "person.badge.shield.exclamationmark"
        case .serverCertificateUntrusted, .serverNameMismatch, .secureConnectionFailed: "exclamationmark.shield"
        case .offline: "wifi.slash"
        case .timedOut: "clock.badge.exclamationmark"
        case .connectionLost, .hostNotFound, .serverUnreachable, .generic: "exclamationmark.triangle"
        }
    }

    /// The fix lives in settings (token host list, bundled organization roots).
    var suggestsSettings: Bool {
        kind == .clientCertificateRequested || kind == .serverCertificateUntrusted
    }

    /// - Parameters:
    ///   - issue: recent token problem for the failed host.
    ///   - proxyError: recent `ProxyEvent.failed` text for the failed host.
    ///   - urlError: the error WebKit reported for the navigation.
    ///   - isTokenHost: the host is in the token list (its traffic goes through mTLS in the proxy).
    /// - Returns: nil when the navigation was cancelled rather than failed (user navigated away,
    ///   unsupported scheme), so no error page should be shown.
    static func from(issue: IdentityStatus?, proxyError: String?, urlError: NSError?, isTokenHost: Bool = false) -> BrowserError? {
        if let urlError, isCancellation(urlError) { return nil }
        let details = detailsText(issue: issue, proxyError: proxyError, urlError: urlError)
        if let issue, let error = fromIssue(issue, details: details) { return error }
        if let proxyError, let error = fromProxyError(proxyError, details: details) { return error }
        if let urlError, let error = fromURLError(urlError, isTokenHost: isTokenHost, details: details) { return error }
        return BrowserError(
            kind: .generic,
            title: "Не удалось открыть страницу",
            message: urlError?.localizedDescription ?? "Произошла ошибка при загрузке страницы.",
            hint: nil,
            details: details
        )
    }

    /// Navigations replaced by another one or stopped by our policy are not failures.
    static func isCancellation(_ error: NSError) -> Bool {
        (error.domain == NSURLErrorDomain && error.code == NSURLErrorCancelled)
            // WebKitErrorFrameLoadInterruptedByPolicyChange: decidePolicy returned .cancel or a download started.
            || (error.domain == "WebKitErrorDomain" && error.code == 102)
    }

    // MARK: Token

    private static func fromIssue(_ issue: IdentityStatus, details: String?) -> BrowserError? {
        switch issue {
        case .tokenMissing:
            return BrowserError(
                kind: .tokenMissing,
                title: "Токен не подключён",
                message: "Этот сайт требует вход по сертификату с Рутокена, но токен не найден.",
                hint: "Подключите USB-токен Рутокен к iPhone, подождите пару секунд и нажмите «Повторить».",
                details: details
            )
        case .noCertificate:
            return BrowserError(
                kind: .noCertificate,
                title: "Нет подходящего сертификата",
                message: "На подключённом токене нет действующего сертификата для входа на сайты.",
                hint: "Проверьте срок действия сертификата на вкладке «Токен» или подключите другой токен.",
                details: details
            )
        case .pinCancelled:
            return BrowserError(
                kind: .pinCancelled,
                title: "Вход отменён",
                message: "Ввод PIN-кода отменён, поэтому сайт не получил сертификат с токена.",
                hint: "Нажмите «Повторить» и введите PIN-код токена.",
                details: details
            )
        case .loginFailed(_, let reason):
            if isPinLocked(reason) { return pinLocked(details: details) }
            return BrowserError(
                kind: .tokenLoginFailed,
                title: "Не удалось войти на токен",
                message: "Токен не выполнил вход: \(reason).",
                hint: "Проверьте, что токен подключён, и нажмите «Повторить».",
                details: details
            )
        case .signedIn:
            return nil
        }
    }

    private static func pinLocked(details: String?) -> BrowserError {
        BrowserError(
            kind: .pinLocked,
            title: "PIN-код заблокирован",
            message: "PIN-код токена введён неверно слишком много раз и заблокирован.",
            hint: "Обратитесь к администратору, чтобы разблокировать токен.",
            details: details
        )
    }

    private static func isPinLocked(_ text: String) -> Bool {
        let text = text.lowercased()
        return text.contains("pinlocked") || text.contains("pin заблокирован") || text.contains("pin_locked")
    }

    // MARK: Proxy

    /// Patterns follow `String(describing:)` of NIO/NIOSSL/TokenKit errors, e.g.
    /// `handshakeFailed(BoringSSLError.sslError([... SSL routines:OPENSSL_internal:CERTIFICATE_VERIFY_FAILED]))`.
    /// BoringSSL `*_ALERT_*` reasons are alerts received from the server.
    private static func fromProxyError(_ error: String, details: String?) -> BrowserError? {
        let text = error.lowercased()
        func has(_ patterns: String...) -> Bool { patterns.contains { text.contains($0) } }

        if isPinLocked(text) { return pinLocked(details: details) }
        if has("tokennotpresent", "токен отключён") {
            return fromIssue(.tokenMissing(host: ""), details: details)
        }
        if has("cancellationerror") {
            return fromIssue(.pinCancelled(host: ""), details: details)
        }
        if has("certificate_required", "alert_bad_certificate", "alert_certificate_unknown",
               "alert_certificate_revoked", "alert_certificate_expired", "alert_unsupported_certificate",
               "alert_unknown_ca", "alert_access_denied") {
            return BrowserError(
                kind: .clientCertificateRejected,
                title: "Сервер не принял сертификат",
                message: "Сервер отклонил сертификат с токена: он мог истечь, быть отозван или не подходить для этого сайта.",
                hint: "Проверьте, что на токене нужный сертификат, или обратитесь к администратору сайта.",
                details: details
            )
        }
        if has("failedtovalidatehostname", "hostname_mismatch", "unabletovalidatehostname") {
            return BrowserError(
                kind: .serverNameMismatch,
                title: "Сертификат сервера выдан для другого адреса",
                message: "Имя в сертификате сервера не совпадает с адресом сайта. Соединение прервано, чтобы защитить ваши данные.",
                hint: "Проверьте адрес сайта.",
                details: details
            )
        }
        if has("certificate_verify_failed", "unable_to_get_local_issuer", "unable_to_get_issuer",
               "self_signed", "unabletovalidatecertificate", "untrusted", "certificate_has_expired", "cert_has_expired") {
            return serverUntrusted(details: details)
        }
        if has("handshake_failure", "handshakefailed", "no_shared_cipher", "protocol_version",
               "wrong_version_number", "unsupported_protocol", "sslerror", "niosslerror") {
            return secureConnectionFailed(details: details)
        }
        if has("dns error", "unknown(host", "nodename nor servname", "name or service not known", "no address associated") {
            return hostNotFound(details: details)
        }
        if has("connection refused", "connecttimeout", "timed out", "connection reset",
               "network is unreachable", "host is down", "no route to host", "nioconnectionerror") {
            return serverUnreachable(details: details)
        }
        return nil
    }

    private static func serverUntrusted(details: String?) -> BrowserError {
        BrowserError(
            kind: .serverCertificateUntrusted,
            title: "Сертификат сервера не доверенный",
            message: "Не удалось проверить сертификат сервера: он выпущен неизвестным центром сертификации, просрочен или подменён. Соединение прервано, чтобы защитить ваши данные.",
            hint: "Если это внутренний сайт организации, корневой сертификат организации должен быть в сборке приложения (список — в настройках).",
            details: details
        )
    }

    private static func secureConnectionFailed(details: String?) -> BrowserError {
        BrowserError(
            kind: .secureConnectionFailed,
            title: "Не удалось установить защищённое соединение",
            message: "Сервер прервал TLS-соединение. Возможно, он не принял сертификат с токена или не поддерживает нужную версию протокола.",
            hint: nil,
            details: details
        )
    }

    private static func hostNotFound(details: String?) -> BrowserError {
        BrowserError(
            kind: .hostNotFound,
            title: "Сервер не найден",
            message: "Не удалось найти сервер с таким адресом.",
            hint: "Проверьте адрес. Внутренние сайты организации могут быть доступны только из её сети или через VPN.",
            details: details
        )
    }

    private static func serverUnreachable(details: String?) -> BrowserError {
        BrowserError(
            kind: .serverUnreachable,
            title: "Сервер недоступен",
            message: "Не удалось подключиться к серверу: он не отвечает или отклоняет соединения.",
            hint: "Внутренние сайты организации могут быть доступны только из её сети или через VPN.",
            details: details
        )
    }

    // MARK: WebKit

    private static func fromURLError(_ error: NSError, isTokenHost: Bool, details: String?) -> BrowserError? {
        guard error.domain == NSURLErrorDomain else { return nil }
        switch error.code {
        case NSURLErrorNotConnectedToInternet, NSURLErrorDataNotAllowed, NSURLErrorInternationalRoamingOff:
            return BrowserError(
                kind: .offline,
                title: "Нет подключения к интернету",
                message: "iPhone не подключён к сети.",
                hint: "Проверьте Wi-Fi или сотовую связь и нажмите «Повторить».",
                details: details
            )
        case NSURLErrorTimedOut:
            return BrowserError(
                kind: .timedOut,
                title: "Сервер не ответил вовремя",
                message: "Сервер слишком долго не отвечает.",
                hint: "Попробуйте ещё раз немного позже.",
                details: details
            )
        case NSURLErrorCannotFindHost, NSURLErrorDNSLookupFailed:
            return hostNotFound(details: details)
        case NSURLErrorCannotConnectToHost:
            return serverUnreachable(details: details)
        case NSURLErrorServerCertificateUntrusted, NSURLErrorServerCertificateHasUnknownRoot,
             NSURLErrorServerCertificateHasBadDate, NSURLErrorServerCertificateNotYetValid:
            return serverUntrusted(details: details)
        case NSURLErrorClientCertificateRequired, NSURLErrorClientCertificateRejected:
            // Token hosts get their certificate from the proxy; WebKit sees this only for other sites.
            return BrowserError(
                kind: .clientCertificateRequested,
                title: "Сайт требует сертификат",
                message: "Сервер запросил клиентский сертификат, но этого сайта нет в списке сайтов с входом по токену.",
                hint: "Добавьте сайт в настройках в «Сайты с входом по токену» и нажмите «Повторить».",
                details: details
            )
        case NSURLErrorSecureConnectionFailed:
            return secureConnectionFailed(details: details)
        case NSURLErrorNetworkConnectionLost:
            return BrowserError(
                kind: .connectionLost,
                title: "Соединение с сервером прервано",
                message: "Сервер закрыл соединение, не ответив.",
                hint: isTokenHost
                    ? "Сайт входит по токену: проверьте, что токен подключён и на нём действующий сертификат, затем нажмите «Повторить»."
                    : nil,
                details: details
            )
        default:
            return nil
        }
    }

    private static func detailsText(issue: IdentityStatus?, proxyError: String?, urlError: NSError?) -> String? {
        var lines: [String] = []
        switch issue {
        case .tokenMissing(let host): lines.append("Токен: не подключён (\(host))")
        case .noCertificate(let host): lines.append("Токен: нет сертификата для входа (\(host))")
        case .pinCancelled(let host): lines.append("Токен: ввод PIN отменён (\(host))")
        case .loginFailed(let host, let reason): lines.append("Токен: \(reason) (\(host))")
        case .signedIn, nil: break
        }
        if let proxyError { lines.append("Прокси: \(proxyError)") }
        if let urlError { lines.append("WebKit: \(urlError.domain) \(urlError.code): \(urlError.localizedDescription)") }
        return lines.isEmpty ? nil : lines.joined(separator: "\n")
    }
}
