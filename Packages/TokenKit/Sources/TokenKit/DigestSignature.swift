import CPkcs11
import Foundation
import Security

public enum HashAlgorithm: Sendable, CaseIterable {
    case sha1, sha224, sha256, sha384, sha512

    public var digestLength: Int {
        switch self {
        case .sha1: 20
        case .sha224: 28
        case .sha256: 32
        case .sha384: 48
        case .sha512: 64
        }
    }

    var mechanism: CK_MECHANISM_TYPE {
        switch self {
        case .sha1: CKM_SHA_1
        case .sha224: CKM_SHA224
        case .sha256: CKM_SHA256
        case .sha384: CKM_SHA384
        case .sha512: CKM_SHA512
        }
    }

    var mgf: CK_RSA_PKCS_MGF_TYPE {
        switch self {
        case .sha1: CKG_MGF1_SHA1
        case .sha224: CKG_MGF1_SHA224
        case .sha256: CKG_MGF1_SHA256
        case .sha384: CKG_MGF1_SHA384
        case .sha512: CKG_MGF1_SHA512
        }
    }

    /// DER prefix of the PKCS#1 v1.5 DigestInfo structure (RFC 8017, section 9.2, note 1).
    var digestInfoPrefix: [UInt8] {
        switch self {
        case .sha1: [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14]
        case .sha224: [0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c]
        case .sha256: [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]
        case .sha384: [0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30]
        case .sha512: [0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40]
        }
    }
}

/// RSA signature over an already computed digest, the form in which Security.framework
/// (and so the system TLS stack) hands signing requests to a CryptoTokenKit token.
public enum DigestSignatureAlgorithm: Hashable, Sendable {
    case pkcs1v15(HashAlgorithm)
    case pss(HashAlgorithm)
    /// Raw RSA: the caller supplies the fully padded block.
    case raw

    /// Maps the Security.framework algorithm requested from a token key.
    public init?(_ algorithm: SecKeyAlgorithm) {
        let table: [SecKeyAlgorithm: DigestSignatureAlgorithm] = [
            .rsaSignatureDigestPKCS1v15SHA1: .pkcs1v15(.sha1),
            .rsaSignatureDigestPKCS1v15SHA224: .pkcs1v15(.sha224),
            .rsaSignatureDigestPKCS1v15SHA256: .pkcs1v15(.sha256),
            .rsaSignatureDigestPKCS1v15SHA384: .pkcs1v15(.sha384),
            .rsaSignatureDigestPKCS1v15SHA512: .pkcs1v15(.sha512),
            .rsaSignatureDigestPSSSHA1: .pss(.sha1),
            .rsaSignatureDigestPSSSHA224: .pss(.sha224),
            .rsaSignatureDigestPSSSHA256: .pss(.sha256),
            .rsaSignatureDigestPSSSHA384: .pss(.sha384),
            .rsaSignatureDigestPSSSHA512: .pss(.sha512),
            .rsaSignatureRaw: .raw
        ]
        guard let match = table[algorithm] else { return nil }
        self = match
    }

    /// Algorithms a token key advertises to Security.framework, best first.
    public static let securityAlgorithms: [SecKeyAlgorithm] = [
        .rsaSignatureDigestPSSSHA256, .rsaSignatureDigestPSSSHA384, .rsaSignatureDigestPSSSHA512,
        .rsaSignatureDigestPKCS1v15SHA256, .rsaSignatureDigestPKCS1v15SHA384, .rsaSignatureDigestPKCS1v15SHA512,
        .rsaSignatureDigestPKCS1v15SHA1, .rsaSignatureRaw
    ]

    var mechanism: CK_MECHANISM_TYPE {
        switch self {
        case .pkcs1v15: CKM_RSA_PKCS
        case .pss: CKM_RSA_PKCS_PSS
        case .raw: CKM_RSA_X_509
        }
    }

    var pssParams: CK_RSA_PKCS_PSS_PARAMS? {
        guard case .pss(let hash) = self else { return nil }
        return CK_RSA_PKCS_PSS_PARAMS(hashAlg: hash.mechanism, mgf: hash.mgf, sLen: CK_ULONG(hash.digestLength))
    }

    /// Bytes passed to C_Sign: DigestInfo for PKCS#1 v1.5, the bare digest for PSS, the block for raw.
    func tokenInput(for digest: Data) throws -> Data {
        switch self {
        case .pkcs1v15(let hash):
            guard digest.count == hash.digestLength else { throw Pkcs11Error.function("digest length", rv: CKR_DATA_LEN_RANGE) }
            return Data(hash.digestInfoPrefix) + digest
        case .pss(let hash):
            guard digest.count == hash.digestLength else { throw Pkcs11Error.function("digest length", rv: CKR_DATA_LEN_RANGE) }
            return digest
        case .raw:
            return digest
        }
    }
}
