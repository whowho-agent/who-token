import Foundation
import Security
import X509

public struct TokenInfo: Identifiable, Hashable, Sendable {
    public var id: UInt { slot }
    public let slot: UInt
    public let label: String
    public let model: String
    public let serialNumber: String
    public let firmwareVersion: String
    public let userPinRetriesLeft: Int?
    public let userPinMaxRetries: Int?
    public let isPinLocked: Bool
}

public struct TokenCertificate: Identifiable, Hashable, Sendable {
    /// PKCS#11 `CKA_ID`; links the certificate to its private key on the token.
    public let keyID: Data
    public let label: String
    public let der: Data
    public let subject: String
    public let commonName: String?
    public let issuer: String
    public let notValidBefore: Date
    public let notValidAfter: Date
    public let isClientAuth: Bool

    public var id: Data { der }

    public init(keyID: Data, label: String, der: Data) throws {
        let certificate = try Certificate(derEncoded: Array(der))
        self.keyID = keyID
        self.label = label
        self.der = der
        subject = certificate.subject.description
        commonName = certificate.subject.lazy
            .flatMap { $0 }
            .first { $0.type == .RDNAttributeType.commonName }
            .map { String(describing: $0.value) }
        issuer = certificate.issuer.description
        notValidBefore = certificate.notValidBefore
        notValidAfter = certificate.notValidAfter
        let usages = (try? certificate.extensions.extendedKeyUsage).map(Array.init) ?? []
        // No EKU extension means the key is not restricted.
        isClientAuth = usages.isEmpty || usages.contains(.clientAuth)
    }

    public func isValid(at date: Date = Date()) -> Bool {
        notValidBefore <= date && date <= notValidAfter
    }

    /// Certificates suitable for TLS client authentication, most recently issued first.
    public static func usableForClientAuth(_ certificates: [TokenCertificate], at date: Date = Date()) -> [TokenCertificate] {
        certificates
            .filter { $0.isClientAuth && $0.isValid(at: date) }
            .sorted { $0.notValidBefore > $1.notValidBefore }
    }

    /// Verifies a signature produced by the token against this certificate's public key.
    public func verify(signature: Data, of message: Data, algorithm: SignatureAlgorithm) -> Bool {
        verify(signature: signature, of: message, secKeyAlgorithm: algorithm.secKeyAlgorithm)
    }

    /// Same for any Security.framework algorithm, e.g. digest-based ones used by CryptoTokenKit.
    public func verify(signature: Data, of data: Data, secKeyAlgorithm: SecKeyAlgorithm) -> Bool {
        guard let secCertificate = SecCertificateCreateWithData(nil, der as CFData),
              let publicKey = SecCertificateCopyKey(secCertificate) else { return false }
        return SecKeyVerifySignature(publicKey, secKeyAlgorithm, data as CFData, signature as CFData, nil)
    }
}
