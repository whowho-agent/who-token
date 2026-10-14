import CryptoKit
import Foundation
import Security
import X509

/// Root CA that anchors a site's server certificate, found so it can be installed on the device
/// as a configuration profile. The user must compare `sha256Fingerprint` with the one published by
/// their IT department: the root is fetched over the very connection that isn't trusted yet.
public struct RootCertificate: Sendable, Equatable {
    public let der: Data
    public let name: String
    public let subject: String
    public let notValidAfter: Date
    /// "AB:CD:…" upper-case hex, 32 bytes.
    public let sha256Fingerprint: String
    /// The root actually anchors the server certificate presented for `host` (checked with SecTrust).
    public let anchorsHost: Bool
    /// Chain as the server sent it, leaf first, by common name.
    public let serverChain: [String]
    /// The root was downloaded from the issuer URL in the chain (it is rarely sent by servers).
    public let downloadedFrom: URL?

    public init(der: Data, host: String, serverChain: [Data], downloadedFrom: URL?) throws {
        let certificate = try Certificate(derEncoded: Array(der))
        self.der = der
        name = Self.commonName(certificate) ?? certificate.subject.description
        subject = certificate.subject.description
        notValidAfter = certificate.notValidAfter
        sha256Fingerprint = SHA256.hash(data: der).map { String(format: "%02X", $0) }.joined(separator: ":")
        self.serverChain = serverChain.compactMap { try? Certificate(derEncoded: Array($0)) }.map { Self.commonName($0) ?? $0.subject.description }
        self.downloadedFrom = downloadedFrom
        anchorsHost = Self.anchors(root: der, chain: serverChain, host: host)
    }

    /// Configuration profile installing this certificate as a trusted root.
    public func mobileConfig() -> Data {
        let rootUUID = UUID().uuidString
        let profileUUID = UUID().uuidString
        let escapedName = name
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
        let plist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
          <key>PayloadContent</key>
          <array>
            <dict>
              <key>PayloadCertificateFileName</key><string>\(escapedName).cer</string>
              <key>PayloadContent</key><data>\(der.base64EncodedString())</data>
              <key>PayloadDisplayName</key><string>\(escapedName)</string>
              <key>PayloadIdentifier</key><string>local.rutoken-safari.root.\(rootUUID)</string>
              <key>PayloadType</key><string>com.apple.security.root</string>
              <key>PayloadUUID</key><string>\(rootUUID)</string>
              <key>PayloadVersion</key><integer>1</integer>
            </dict>
          </array>
          <key>PayloadDisplayName</key><string>Корневой сертификат: \(escapedName)</string>
          <key>PayloadIdentifier</key><string>local.rutoken-safari.profile.\(profileUUID)</string>
          <key>PayloadRemovalDisallowed</key><false/>
          <key>PayloadType</key><string>Configuration</string>
          <key>PayloadUUID</key><string>\(profileUUID)</string>
          <key>PayloadVersion</key><integer>1</integer>
        </dict>
        </plist>
        """
        return Data(plist.utf8)
    }

    private static func commonName(_ certificate: Certificate) -> String? {
        certificate.subject.lazy.flatMap { $0 }
            .first { $0.type == .RDNAttributeType.commonName }
            .map { String(describing: $0.value) }
    }

    private static func anchors(root: Data, chain: [Data], host: String) -> Bool {
        let certificates = chain.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        guard let anchor = SecCertificateCreateWithData(nil, root as CFData), !certificates.isEmpty else { return false }
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(certificates as CFArray, SecPolicyCreateSSL(true, host as CFString), &trust) == errSecSuccess,
              let trust else { return false }
        SecTrustSetAnchorCertificates(trust, [anchor] as CFArray)
        SecTrustSetAnchorCertificatesOnly(trust, true)
        SecTrustSetNetworkFetchAllowed(trust, true)
        return SecTrustEvaluateWithError(trust, nil)
    }
}

public enum RootCertificateError: Error, CustomStringConvertible {
    case invalidHost
    case noServerCertificates(String)
    case rootNotFound
    case download(URL, String)

    public var description: String {
        switch self {
        case .invalidHost: "Введите адрес сайта, например wiki.example.com"
        case .noServerCertificates(let reason): "Не удалось получить сертификат сервера: \(reason)"
        case .rootNotFound: "Сервер не прислал корневой сертификат, и в цепочке нет ссылки, где его скачать. Попросите профиль у ИТ."
        case .download(let url, let reason): "Не удалось скачать сертификат издателя (\(url.absoluteString)): \(reason)"
        }
    }
}

/// Finds the root CA of a site: the server's chain, then issuer certificates by their AIA "CA Issuers"
/// URLs until a self-signed certificate is reached.
public enum RootCertificateFinder {
    public static func find(siteAddress: String) async throws -> RootCertificate {
        guard let (host, port) = parse(siteAddress) else { throw RootCertificateError.invalidHost }
        let chain = try await ServerChainFetcher.chain(host: host, port: port)
        guard var top = chain.last else { throw RootCertificateError.noServerCertificates("пустая цепочка") }
        var downloadedFrom: URL?
        for _ in 0..<4 {
            if isSelfSigned(top) {
                return try RootCertificate(der: top, host: host, serverChain: chain, downloadedFrom: downloadedFrom)
            }
            guard let url = issuerURL(of: top) else { throw RootCertificateError.rootNotFound }
            top = try await download(url)
            downloadedFrom = url
        }
        throw RootCertificateError.rootNotFound
    }

    /// Whether iOS trusts the site's server certificate as is (system and user-trusted roots),
    /// i.e. Safari opens it without a certificate warning.
    public static func isTrustedBySystem(siteAddress: String) async throws -> Bool {
        guard let (host, port) = parse(siteAddress) else { throw RootCertificateError.invalidHost }
        let chain = try await ServerChainFetcher.chain(host: host, port: port)
        let certificates = chain.compactMap { SecCertificateCreateWithData(nil, $0 as CFData) }
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(certificates as CFArray, SecPolicyCreateSSL(true, host as CFString), &trust) == errSecSuccess,
              let trust else { return false }
        SecTrustSetNetworkFetchAllowed(trust, true)
        return SecTrustEvaluateWithError(trust, nil)
    }

    static func parse(_ address: String) -> (String, Int)? {
        var text = address.trimmingCharacters(in: .whitespacesAndNewlines)
        if !text.contains("://") { text = "https://" + text }
        guard let url = URL(string: text), let host = url.host(), !host.isEmpty else { return nil }
        return (host, url.port ?? 443)
    }

    static func isSelfSigned(_ der: Data) -> Bool {
        guard let certificate = try? Certificate(derEncoded: Array(der)), certificate.subject == certificate.issuer else {
            return false
        }
        return certificate.publicKey.isValidSignature(certificate.signature, for: certificate)
    }

    static func issuerURL(of der: Data) -> URL? {
        guard let certificate = try? Certificate(derEncoded: Array(der)),
              let access = try? certificate.extensions.authorityInformationAccess else { return nil }
        return access.lazy
            .filter { $0.method == .issuingCA }
            .compactMap { description -> URL? in
                guard case .uniformResourceIdentifier(let uri) = description.location else { return nil }
                return URL(string: uri).flatMap { ["http", "https"].contains($0.scheme) ? $0 : nil }
            }
            .first
    }

    /// Issuer certificates are published as DER (.crt/.cer) or PEM.
    static func download(_ url: URL) async throws -> Data {
        do {
            let (data, _) = try await URLSession.shared.data(from: url)
            if (try? Certificate(derEncoded: Array(data))) != nil { return data }
            let pem = String(decoding: data, as: UTF8.self)
            if let document = try? Certificate(pemEncoded: pem) {
                return Data(try document.serializeAsPEM().derBytes)
            }
            throw RootCertificateError.download(url, "это не сертификат")
        } catch let error as RootCertificateError {
            throw error
        } catch {
            throw RootCertificateError.download(url, error.localizedDescription)
        }
    }
}

/// Reads the certificate chain a server presents, without trusting it: the handshake is cancelled at
/// the server-trust challenge, before any client certificate (token) would be requested.
private final class ServerChainFetcher: NSObject, URLSessionDelegate, @unchecked Sendable {
    private var chain: [Data] = []
    private let lock = NSLock()

    static func chain(host: String, port: Int) async throws -> [Data] {
        let fetcher = ServerChainFetcher()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 15
        let session = URLSession(configuration: configuration, delegate: fetcher, delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        var components = URLComponents()
        components.scheme = "https"
        components.host = host
        components.port = port == 443 ? nil : port
        components.path = "/"
        do {
            _ = try await session.data(from: components.url!)
        } catch {
            if fetcher.captured.isEmpty {
                throw RootCertificateError.noServerCertificates(error.localizedDescription)
            }
        }
        guard !fetcher.captured.isEmpty else { throw RootCertificateError.noServerCertificates("сервер не прислал сертификаты") }
        return fetcher.captured
    }

    private var captured: [Data] { lock.withLock { chain } }

    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust else { return (.cancelAuthenticationChallenge, nil) }
        let certificates = (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? []
        lock.withLock { chain = certificates.map { SecCertificateCopyData($0) as Data } }
        return (.cancelAuthenticationChallenge, nil)
    }
}
