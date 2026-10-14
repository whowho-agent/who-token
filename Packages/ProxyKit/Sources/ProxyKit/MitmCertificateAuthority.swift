import Crypto
import Foundation
import NIOConcurrencyHelpers
import NIOSSL
import SwiftASN1
import X509

/// In-memory CA for the local proxy: issues a leaf certificate per intercepted host.
/// Keys never leave process memory; a new CA is generated on every app launch.
public final class MitmCertificateAuthority: Sendable {
    /// DER of the CA certificate, used by the WebView delegate as the only trust anchor for intercepted hosts.
    public let caCertificateDER: Data

    private let caKey: P256.Signing.PrivateKey
    private let caName: DistinguishedName
    private let leafKey: P256.Signing.PrivateKey
    private let contexts = NIOLockedValueBox<[String: NIOSSLContext]>([:])

    public init() throws {
        caKey = P256.Signing.PrivateKey()
        leafKey = P256.Signing.PrivateKey()
        caName = try DistinguishedName {
            OrganizationName("RutokenBrowser")
            CommonName("RutokenBrowser Local Proxy CA")
        }
        let now = Date()
        let ca = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: .init(caKey.publicKey),
            notValidBefore: now.addingTimeInterval(-3600),
            notValidAfter: now.addingTimeInterval(30 * 86_400),
            issuer: caName,
            subject: caName,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 0))
                Critical(KeyUsage(keyCertSign: true, cRLSign: true))
            },
            issuerPrivateKey: .init(caKey)
        )
        caCertificateDER = try Self.der(ca)
    }

    /// TLS server context presenting a certificate for `host` to the WebView.
    public func serverContext(for host: String) throws -> NIOSSLContext {
        if let cached = contexts.withLockedValue({ $0[host] }) { return cached }
        let leaf = try issueLeaf(for: host)
        var configuration = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(try NIOSSLCertificate(bytes: Array(leaf), format: .der))],
            privateKey: .privateKey(try NIOSSLPrivateKey(bytes: Array(leafKey.pemRepresentation.utf8), format: .pem))
        )
        // Bytes are relayed as is, so both sides must speak the same protocol; upstream is pinned to HTTP/1.1.
        configuration.applicationProtocols = ["http/1.1"]
        let context = try NIOSSLContext(configuration: configuration)
        contexts.withLockedValue { $0[host] = context }
        return context
    }

    func issueLeaf(for host: String) throws -> Data {
        let now = Date()
        let name: GeneralName
        if let ip = IPAddressBytes(host) {
            name = .ipAddress(ASN1OctetString(contentBytes: ArraySlice(ip.bytes)))
        } else {
            name = .dnsName(host)
        }
        let leaf = try Certificate(
            version: .v3,
            serialNumber: Certificate.SerialNumber(),
            publicKey: .init(leafKey.publicKey),
            notValidBefore: now.addingTimeInterval(-3600),
            // Apple rejects TLS server certificates valid for more than 825 days, even from custom anchors.
            notValidAfter: now.addingTimeInterval(7 * 86_400),
            issuer: caName,
            subject: try DistinguishedName { CommonName(host) },
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.notCertificateAuthority)
                Critical(KeyUsage(digitalSignature: true))
                try ExtendedKeyUsage([.serverAuth])
                SubjectAlternativeNames([name])
            },
            issuerPrivateKey: .init(caKey)
        )
        return try Self.der(leaf)
    }

    private static func der(_ certificate: Certificate) throws -> Data {
        var serializer = DER.Serializer()
        try serializer.serialize(certificate)
        return Data(serializer.serializedBytes)
    }
}

private struct IPAddressBytes {
    let bytes: [UInt8]

    init?(_ string: String) {
        var v4 = in_addr()
        var v6 = in6_addr()
        if inet_pton(AF_INET, string, &v4) == 1 {
            bytes = withUnsafeBytes(of: &v4) { Array($0) }
        } else if inet_pton(AF_INET6, string, &v6) == 1 {
            bytes = withUnsafeBytes(of: &v6) { Array($0) }
        } else {
            return nil
        }
    }
}
