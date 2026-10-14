import Foundation
import NIOSSL
import TokenKit

/// Client certificate and token-backed key to present to an upstream server.
public struct ClientIdentity: Sendable {
    public let certificate: TokenCertificate
    /// Intermediate CA certificates (DER) sent after the leaf, if the server needs the full chain.
    public let intermediates: [Data]
    public let privateKey: TokenPrivateKey

    public init(certificate: TokenCertificate, intermediates: [Data] = [], privateKey: TokenPrivateKey) {
        self.certificate = certificate
        self.intermediates = intermediates
        self.privateKey = privateKey
    }
}

/// Supplies the identity for an intercepted host; may ask the user for the PIN before returning.
public protocol ClientIdentityProvider: Sendable {
    func identity(for host: String) async throws -> ClientIdentity?
}

enum UpstreamTLS {
    static func context(
        identity: ClientIdentity?,
        extraTrustRootsPEM: [Data],
        version: TLSVersionChoice = .automatic
    ) throws -> NIOSSLContext {
        var configuration = TLSConfiguration.makeClientConfiguration()
        if let identity {
            configuration.certificateChain = try ([identity.certificate.der] + identity.intermediates)
                .map { .certificate(try NIOSSLCertificate(bytes: Array($0), format: .der)) }
            configuration.privateKey = .privateKey(NIOSSLPrivateKey(customPrivateKey: identity.privateKey))
        }
        configuration.minimumTLSVersion = version == .tls13 ? .tlsv13 : .tlsv12
        configuration.maximumTLSVersion = version == .tls12 ? .tlsv12 : .tlsv13
        configuration.applicationProtocols = ["http/1.1"]
        if !extraTrustRootsPEM.isEmpty {
            let certificates = try extraTrustRootsPEM.flatMap { try NIOSSLCertificate.fromPEMBytes(Array($0)) }
            configuration.additionalTrustRoots = [.certificates(certificates)]
        }
        return try NIOSSLContext(configuration: configuration)
    }

    /// SNI must not carry an IP address; certificate IP SANs are checked against the peer address instead.
    static func serverHostname(_ host: String) -> String? {
        host.isIPAddress ? nil : host
    }
}
