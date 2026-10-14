import Foundation
import Security
import Testing
@testable import TokenKit

private func fixture(_ name: String) throws -> Data {
    let url = try #require(Bundle.module.url(forResource: name, withExtension: "der", subdirectory: "Fixtures"))
    return try Data(contentsOf: url)
}

@Suite struct TokenCertificateTests {
    @Test func parsesClientAuthCertificate() throws {
        let cert = try TokenCertificate(keyID: Data([1, 2]), label: "test", der: fixture("client-auth"))
        #expect(cert.commonName == "Test Client")
        #expect(cert.subject.contains("TokenKit Tests"))
        #expect(cert.isClientAuth)
        #expect(cert.isValid())
    }

    @Test func serverOnlyCertificateIsNotClientAuth() throws {
        let cert = try TokenCertificate(keyID: Data([3]), label: "srv", der: fixture("server-auth"))
        #expect(!cert.isClientAuth)
    }

    @Test func usableForClientAuthDropsExpiredAndServerOnly() throws {
        let client = try TokenCertificate(keyID: Data([1]), label: "c", der: fixture("client-auth"))
        let server = try TokenCertificate(keyID: Data([2]), label: "s", der: fixture("server-auth"))
        #expect(TokenCertificate.usableForClientAuth([client, server]) == [client])
        let farFuture = client.notValidAfter.addingTimeInterval(86_400)
        #expect(TokenCertificate.usableForClientAuth([client], at: farFuture).isEmpty)
    }

    @Test(arguments: SignatureAlgorithm.allCases)
    func verifiesSignaturesFromMatchingKey(algorithm: SignatureAlgorithm) throws {
        let cert = try TokenCertificate(keyID: Data([1]), label: "c", der: fixture("client-auth"))
        let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPrivate]
        let key = try #require(SecKeyCreateWithData(fixture("client-auth-key.pkcs1") as CFData, attributes as CFDictionary, nil))
        let message = Data("TLS 1.3, client CertificateVerify".utf8)
        let signature = try #require(SecKeyCreateSignature(key, algorithm.secKeyAlgorithm, message as CFData, nil) as Data?)

        #expect(cert.verify(signature: signature, of: message, algorithm: algorithm))
        #expect(!cert.verify(signature: signature, of: Data("tampered".utf8), algorithm: algorithm))
    }
}

@Suite struct SignatureAlgorithmTests {
    @Test func pssUsesDigestLengthSalt() {
        #expect(SignatureAlgorithm.rsaPssRsaeSha256.pssParams?.sLen == 32)
        #expect(SignatureAlgorithm.rsaPssRsaeSha384.pssParams?.sLen == 48)
        #expect(SignatureAlgorithm.rsaPssRsaeSha512.pssParams?.sLen == 64)
        #expect(SignatureAlgorithm.rsaPkcs1Sha256.pssParams == nil)
    }
}
