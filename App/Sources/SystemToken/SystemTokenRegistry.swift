import CryptoTokenKit
import Foundation
import Security
import TokenKit

/// Publishes token certificates to the system through the app's CryptoTokenKit extension, so Safari
/// offers them as client identities and asks the extension to sign.
enum SystemTokenRegistry {
    /// The token driver's class id, read from the embedded extension: re-signing may change the app's
    /// bundle id but leaves the extension's `com.apple.ctk.class-id` as built.
    static let extensionID: String = {
        let plist = Bundle.main.builtInPlugInsURL?
            .appending(path: "RutokenTokenExtension.appex/Info.plist")
        let attributes = plist
            .flatMap { NSDictionary(contentsOf: $0) as? [String: Any] }
            .flatMap { $0["NSExtension"] as? [String: Any] }
            .flatMap { $0["NSExtensionAttributes"] as? [String: Any] }
        return attributes?["com.apple.ctk.class-id"] as? String
            ?? (Bundle.main.bundleIdentifier ?? "") + ".TokenExtension"
    }()

    static func tokenID(serialNumber: String) -> String { "\(extensionID):\(serialNumber)" }

    enum RegistryError: Error, CustomStringConvertible {
        case driverNotFound(String)
        case noCertificates

        var description: String {
            switch self {
            case .driverNotFound(let id): "Система не видит расширение \(id)"
            case .noCertificates: "На токене нет действующих сертификатов для входа"
            }
        }
    }

    static func register(token: TokenInfo, certificates: [TokenCertificate]) throws {
        guard let driver = TKTokenDriver.Configuration.driverConfigurations[extensionID] else {
            throw RegistryError.driverNotFound(extensionID)
        }
        guard !certificates.isEmpty else { throw RegistryError.noCertificates }

        let configuration = driver.addTokenConfiguration(for: token.serialNumber)
        configuration.keychainItems = certificates.flatMap { cert -> [TKTokenKeychainItem] in
            guard let secCertificate = SecCertificateCreateWithData(nil, cert.der as CFData),
                  let certItem = TKTokenKeychainCertificate(certificate: secCertificate, objectID: certificateObjectID(cert)),
                  let keyItem = TKTokenKeychainKey(certificate: secCertificate, objectID: cert.keyID) else { return [] }
            certItem.label = cert.label
            keyItem.label = cert.label
            keyItem.canSign = true
            keyItem.canDecrypt = false
            keyItem.canPerformKeyExchange = false
            keyItem.isSuitableForLogin = false
            return [certItem, keyItem]
        }
    }

    static func unregisterAll() {
        guard let driver = TKTokenDriver.Configuration.driverConfigurations[extensionID] else { return }
        for instanceID in driver.tokenConfigurations.keys {
            driver.removeTokenConfiguration(for: instanceID)
        }
    }

    static var registeredSerialNumbers: [String] {
        TKTokenDriver.Configuration.driverConfigurations[extensionID].map { Array($0.tokenConfigurations.keys) } ?? []
    }

    /// Certificate and key items need distinct object IDs; the key keeps the PKCS#11 CKA_ID.
    private static func certificateObjectID(_ cert: TokenCertificate) -> Data {
        Data("cert:".utf8) + cert.keyID
    }
}
