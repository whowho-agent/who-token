import CryptoTokenKit
import Foundation
import Security
import TokenKit

/// Publishes token certificates to the system keychain through the app's CryptoTokenKit extension,
/// so WebKit can use them as ordinary client identities.
enum SystemTokenRegistry {
    static var extensionID: String { (Bundle.main.bundleIdentifier ?? "") + ".TokenExtension" }

    static func tokenID(serialNumber: String) -> String { "\(extensionID):\(serialNumber)" }

    enum RegistryError: Error, CustomStringConvertible {
        case driverNotFound(String)
        case noCertificates

        var description: String {
            switch self {
            case .driverNotFound(let id): "Система не видит расширение \(id)"
            case .noCertificates: "Нет годных для mTLS сертификатов"
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

    /// Client identities backed by registered tokens, as WebKit needs them for a client-certificate challenge.
    static func identities() -> [SecIdentity] {
        registeredSerialNumbers.flatMap { serial -> [SecIdentity] in
            let query: [CFString: Any] = [
                kSecClass: kSecClassIdentity,
                kSecAttrTokenID: tokenID(serialNumber: serial),
                kSecReturnRef: true,
                kSecMatchLimit: kSecMatchLimitAll
            ]
            var result: CFTypeRef?
            guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else { return [] }
            return (result as? [SecIdentity]) ?? []
        }
    }

    /// Spike diagnostics: what the keychain returns for token-backed items.
    static func diagnostics() -> String {
        func count(_ query: [CFString: Any]) -> String {
            var query = query
            query[kSecReturnRef] = true
            query[kSecMatchLimit] = kSecMatchLimitAll
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            return status == errSecSuccess ? "\((result as? [Any])?.count ?? 1)" : "OSStatus \(status)"
        }
        let configuration = TKTokenDriver.Configuration.driverConfigurations[extensionID]
        var lines = [
            "driver: \(configuration == nil ? "не найден" : "есть"), токены: \(registeredSerialNumbers)",
            "все удостоверения: \(count([kSecClass: kSecClassIdentity]))",
            "все сертификаты: \(count([kSecClass: kSecClassCertificate]))"
        ]
        for serial in registeredSerialNumbers {
            let id = tokenID(serialNumber: serial)
            let items = configuration?.tokenConfigurations[serial]?.keychainItems.count ?? 0
            lines.append("\(id): элементов в конфигурации \(items), удостоверений \(count([kSecClass: kSecClassIdentity, kSecAttrTokenID: id])), ключей \(count([kSecClass: kSecClassKey, kSecAttrTokenID: id])), сертификатов \(count([kSecClass: kSecClassCertificate, kSecAttrTokenID: id]))")
        }
        return lines.joined(separator: "\n")
    }

    /// Certificate and key items need distinct object IDs; the key keeps the PKCS#11 CKA_ID.
    private static func certificateObjectID(_ cert: TokenCertificate) -> Data {
        Data("cert:".utf8) + cert.keyID
    }
}
