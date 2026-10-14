import CPkcs11
import Foundation
import Security

/// RSA signature schemes used by TLS 1.2/1.3 client authentication.
/// The token hashes the input itself, so `sign` takes the full message, as BoringSSL's key callback provides.
public enum SignatureAlgorithm: String, CaseIterable, Sendable {
    case rsaPkcs1Sha256 = "rsa_pkcs1_sha256"
    case rsaPkcs1Sha384 = "rsa_pkcs1_sha384"
    case rsaPkcs1Sha512 = "rsa_pkcs1_sha512"
    case rsaPssRsaeSha256 = "rsa_pss_rsae_sha256"
    case rsaPssRsaeSha384 = "rsa_pss_rsae_sha384"
    case rsaPssRsaeSha512 = "rsa_pss_rsae_sha512"

    var mechanism: CK_MECHANISM_TYPE {
        switch self {
        case .rsaPkcs1Sha256: CKM_SHA256_RSA_PKCS
        case .rsaPkcs1Sha384: CKM_SHA384_RSA_PKCS
        case .rsaPkcs1Sha512: CKM_SHA512_RSA_PKCS
        case .rsaPssRsaeSha256: CKM_SHA256_RSA_PKCS_PSS
        case .rsaPssRsaeSha384: CKM_SHA384_RSA_PKCS_PSS
        case .rsaPssRsaeSha512: CKM_SHA512_RSA_PKCS_PSS
        }
    }

    /// PSS parameters as TLS requires them: MGF1 with the same hash, salt length equal to the digest length.
    var pssParams: CK_RSA_PKCS_PSS_PARAMS? {
        switch self {
        case .rsaPssRsaeSha256: CK_RSA_PKCS_PSS_PARAMS(hashAlg: CKM_SHA256, mgf: CKG_MGF1_SHA256, sLen: 32)
        case .rsaPssRsaeSha384: CK_RSA_PKCS_PSS_PARAMS(hashAlg: CKM_SHA384, mgf: CKG_MGF1_SHA384, sLen: 48)
        case .rsaPssRsaeSha512: CK_RSA_PKCS_PSS_PARAMS(hashAlg: CKM_SHA512, mgf: CKG_MGF1_SHA512, sLen: 64)
        default: nil
        }
    }

    /// Matching Security.framework algorithm, used to verify token signatures with the certificate's public key.
    public var secKeyAlgorithm: SecKeyAlgorithm {
        switch self {
        case .rsaPkcs1Sha256: .rsaSignatureMessagePKCS1v15SHA256
        case .rsaPkcs1Sha384: .rsaSignatureMessagePKCS1v15SHA384
        case .rsaPkcs1Sha512: .rsaSignatureMessagePKCS1v15SHA512
        case .rsaPssRsaeSha256: .rsaSignatureMessagePSSSHA256
        case .rsaPssRsaeSha384: .rsaSignatureMessagePSSSHA384
        case .rsaPssRsaeSha512: .rsaSignatureMessagePSSSHA512
        }
    }
}
