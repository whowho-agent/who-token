import Foundation
import Security
import TokenKit

/// A CA certificate bundled with the app (App/TrustRoots, App/ClientChain), shown read-only in settings
/// so the team can check which build carries which organization certificates and when they expire.
struct OrganizationCertificate: Identifiable, Sendable {
    enum Role: Sendable {
        /// Verifies intercepted servers (App/TrustRoots, test stand CA).
        case trustRoot
        /// Sent after the token certificate (App/ClientChain).
        case clientChain
    }

    let id: Data
    let name: String
    let file: String
    let role: Role
    let notValidAfter: Date?

    var isExpired: Bool { notValidAfter.map { $0 < .now } ?? false }

    static func loadBundled(from bundle: Bundle = .main) -> [OrganizationCertificate] {
        func load(_ urls: [URL], role: Role) -> [OrganizationCertificate] {
            urls.sorted { $0.lastPathComponent < $1.lastPathComponent }.flatMap { url in
                guard let pem = try? String(contentsOf: url, encoding: .utf8) else { return [OrganizationCertificate]() }
                return derBlocks(pem).compactMap { make(der: $0, file: url.lastPathComponent, role: role) }
            }
        }
        let roots = (bundle.urls(forResourcesWithExtension: "pem", subdirectory: "TrustRoots") ?? [])
            + [bundle.url(forResource: "stand-ca", withExtension: "pem")].compactMap { $0 }
        let chain = bundle.urls(forResourcesWithExtension: "pem", subdirectory: "ClientChain") ?? []
        return load(roots, role: .trustRoot) + load(chain, role: .clientChain)
    }

    /// A PEM file may hold several certificates.
    static func derBlocks(_ pem: String) -> [Data] {
        var blocks: [Data] = []
        var base64: String?
        for line in pem.split(whereSeparator: \.isNewline).map({ $0.trimmingCharacters(in: .whitespaces) }) {
            if line == "-----BEGIN CERTIFICATE-----" {
                base64 = ""
            } else if line == "-----END CERTIFICATE-----" {
                if let text = base64, let der = Data(base64Encoded: text) { blocks.append(der) }
                base64 = nil
            } else if base64 != nil {
                base64! += line
            }
        }
        return blocks
    }

    private static func make(der: Data, file: String, role: Role) -> OrganizationCertificate? {
        guard let certificate = SecCertificateCreateWithData(nil, der as CFData) else { return nil }
        // Security has no public expiry accessor on iOS; TokenKit already parses X.509.
        let parsed = try? TokenCertificate(keyID: Data(), label: file, der: der)
        // The subject summary is the common name when there is one.
        let name = SecCertificateCopySubjectSummary(certificate).map { $0 as String } ?? parsed?.commonName ?? file
        return OrganizationCertificate(id: der, name: name, file: file, role: role, notValidAfter: parsed?.notValidAfter)
    }
}
