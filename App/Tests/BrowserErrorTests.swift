import Foundation
import Testing

struct BrowserErrorTests {
    private func urlError(_ code: Int) -> NSError {
        NSError(domain: NSURLErrorDomain, code: code, userInfo: [NSLocalizedDescriptionKey: "Сетевое соединение потеряно."])
    }

    // MARK: Cancellation

    @Test func cancelledNavigationShowsNoPage() {
        #expect(BrowserError.from(issue: .tokenMissing(host: "a"), proxyError: nil, urlError: urlError(NSURLErrorCancelled)) == nil)
        let policy = NSError(domain: "WebKitErrorDomain", code: 102)
        #expect(BrowserError.from(issue: nil, proxyError: nil, urlError: policy) == nil)
    }

    // MARK: Token issues win over everything else

    @Test func tokenMissing() throws {
        let error = try #require(BrowserError.from(
            issue: .tokenMissing(host: "lk.example.ru"),
            proxyError: "handshakeFailed(... SSLV3_ALERT_HANDSHAKE_FAILURE)",
            urlError: urlError(NSURLErrorNetworkConnectionLost)
        ))
        #expect(error.kind == .tokenMissing)
        #expect(error.hint?.contains("USB") == true)
        #expect(error.details?.contains("SSLV3_ALERT_HANDSHAKE_FAILURE") == true)
        #expect(error.details?.contains("-1005") == true)
    }

    @Test func otherTokenIssues() {
        #expect(BrowserError.from(issue: .noCertificate(host: "a"), proxyError: nil, urlError: nil)?.kind == .noCertificate)
        #expect(BrowserError.from(issue: .pinCancelled(host: "a"), proxyError: nil, urlError: nil)?.kind == .pinCancelled)
        #expect(BrowserError.from(issue: .loginFailed(host: "a", reason: "PIN заблокирован"), proxyError: nil, urlError: nil)?.kind == .pinLocked)
        let failed = BrowserError.from(issue: .loginFailed(host: "a", reason: "C_Login вернула 0x5"), proxyError: nil, urlError: nil)
        #expect(failed?.kind == .tokenLoginFailed)
        #expect(failed?.message.contains("C_Login") == true)
    }

    @Test func signedInIsNotAnIssue() {
        let error = BrowserError.from(issue: .signedIn, proxyError: nil, urlError: urlError(NSURLErrorTimedOut))
        #expect(error?.kind == .timedOut)
    }

    // MARK: Proxy errors (String(describing:) of NIO / NIOSSL / TokenKit errors)

    @Test(arguments: [
        ("handshakeFailed(NIOSSL.BoringSSLError.sslError([Error: 268435581 error:1000007d:SSL routines:OPENSSL_internal:CERTIFICATE_VERIFY_FAILED]))", BrowserError.Kind.serverCertificateUntrusted),
        ("unableToValidateCertificate", .serverCertificateUntrusted),
        ("NIOSSLExtraError.failedToValidateHostname: Couldn't find lk.example.ru in certificate from peer", .serverNameMismatch),
        ("handshakeFailed(NIOSSL.BoringSSLError.sslError([Error: 268436498 error:10000412:SSL routines:OPENSSL_internal:SSLV3_ALERT_BAD_CERTIFICATE]))", .clientCertificateRejected),
        ("handshakeFailed(NIOSSL.BoringSSLError.sslError([Error: 268436596 error:10000474:SSL routines:OPENSSL_internal:TLSV1_ALERT_CERTIFICATE_REQUIRED]))", .clientCertificateRejected),
        ("handshakeFailed(... SSLV3_ALERT_CERTIFICATE_EXPIRED)", .clientCertificateRejected),
        ("handshakeFailed(... TLSV1_ALERT_UNKNOWN_CA)", .clientCertificateRejected),
        ("handshakeFailed(NIOSSL.BoringSSLError.sslError([Error: 268436496 error:10000410:SSL routines:OPENSSL_internal:SSLV3_ALERT_HANDSHAKE_FAILURE]))", .secureConnectionFailed),
        ("handshakeFailed(... WRONG_VERSION_NUMBER)", .secureConnectionFailed),
        ("DNS error: unknown(host: \"nope.example.ru\", port: 443)", .hostNotFound),
        ("Connection errors: SingleConnectionFailure(target: [IPv4]10.0.0.1/10.0.0.1:443, error: connection reset (error set): Connection refused (errno: 61))", .serverUnreachable),
        ("connectTimeout(TimeAmount(nanoseconds: 15000000000))", .serverUnreachable),
        ("PIN заблокирован", .pinLocked),
        ("Токен отключён", .tokenMissing),
        ("CancellationError()", .pinCancelled),
    ])
    func proxyErrors(text: String, kind: BrowserError.Kind) {
        let error = BrowserError.from(issue: nil, proxyError: text, urlError: urlError(NSURLErrorNetworkConnectionLost))
        #expect(error?.kind == kind)
        #expect(error?.details?.contains(text) == true)
    }

    @Test func unknownProxyErrorFallsBackToWebKitError() {
        let error = BrowserError.from(issue: nil, proxyError: "something odd", urlError: urlError(NSURLErrorTimedOut))
        #expect(error?.kind == .timedOut)
        #expect(error?.details?.contains("something odd") == true)
    }

    // MARK: WebKit errors only

    @Test(arguments: [
        (NSURLErrorNotConnectedToInternet, BrowserError.Kind.offline),
        (NSURLErrorTimedOut, .timedOut),
        (NSURLErrorCannotFindHost, .hostNotFound),
        (NSURLErrorCannotConnectToHost, .serverUnreachable),
        (NSURLErrorServerCertificateUntrusted, .serverCertificateUntrusted),
        (NSURLErrorServerCertificateHasUnknownRoot, .serverCertificateUntrusted),
        (NSURLErrorClientCertificateRequired, .clientCertificateRequested),
        (NSURLErrorSecureConnectionFailed, .secureConnectionFailed),
        (NSURLErrorNetworkConnectionLost, .connectionLost),
        (NSURLErrorBadServerResponse, .generic),
    ])
    func webKitErrors(code: Int, kind: BrowserError.Kind) {
        #expect(BrowserError.from(issue: nil, proxyError: nil, urlError: urlError(code))?.kind == kind)
    }

    @Test func connectionLostOnTokenHostHintsAtToken() {
        let token = BrowserError.from(issue: nil, proxyError: nil, urlError: urlError(NSURLErrorNetworkConnectionLost), isTokenHost: true)
        let other = BrowserError.from(issue: nil, proxyError: nil, urlError: urlError(NSURLErrorNetworkConnectionLost), isTokenHost: false)
        #expect(token?.hint?.contains("токен") == true)
        #expect(other?.hint == nil)
    }

    @Test func settingsSuggestedOnlyWhereTheFixIsThere() {
        #expect(BrowserError.from(issue: nil, proxyError: nil, urlError: urlError(NSURLErrorClientCertificateRequired))?.suggestsSettings == true)
        #expect(BrowserError.from(issue: nil, proxyError: nil, urlError: urlError(NSURLErrorTimedOut))?.suggestsSettings == false)
    }

    @Test func genericKeepsWebKitText() {
        let error = BrowserError.from(issue: nil, proxyError: nil, urlError: NSError(domain: "WebKitErrorDomain", code: 101, userInfo: [NSLocalizedDescriptionKey: "Не удаётся открыть URL"]))
        #expect(error?.kind == .generic)
        #expect(error?.message == "Не удаётся открыть URL")
        #expect(error?.details?.contains("WebKitErrorDomain 101") == true)
    }
}
