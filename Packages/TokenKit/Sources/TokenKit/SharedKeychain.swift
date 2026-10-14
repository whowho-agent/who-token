import Foundation
import Security

/// Small keychain store shared by the app and its CryptoTokenKit extension
/// (keychain access group from the `RBSharedKeychainGroup` Info.plist key).
public enum SharedKeychain {
    public static var accessGroup: String? {
        Bundle.main.object(forInfoDictionaryKey: "RBSharedKeychainGroup") as? String
    }

    public static func set(_ value: Data, account: String) {
        guard let group = accessGroup else { return }
        let query = baseQuery(account: account, group: group)
        SecItemDelete(query as CFDictionary)
        var item = query
        item[kSecValueData] = value
        item[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        SecItemAdd(item as CFDictionary, nil)
    }

    public static func get(account: String) -> Data? {
        guard let group = accessGroup else { return nil }
        var query = baseQuery(account: account, group: group)
        query[kSecReturnData] = true
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else { return nil }
        return result as? Data
    }

    public static func delete(account: String) {
        guard let group = accessGroup else { return }
        SecItemDelete(baseQuery(account: account, group: group) as CFDictionary)
    }

    private static func baseQuery(account: String, group: String) -> [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: "RutokenBrowser",
            kSecAttrAccount: account,
            kSecAttrAccessGroup: group,
            kSecUseDataProtectionKeychain: true
        ]
    }
}

/// Spike diagnostics: the extension runs in its own process, so it leaves a short event log
/// in the shared keychain for the app to display.
public enum ExtensionLog {
    private static let account = "extension-log"

    public static func append(_ line: String) {
        let stamp = Date().formatted(date: .omitted, time: .standard)
        let lines = (read() + ["\(stamp) \(line)"]).suffix(40)
        SharedKeychain.set(Data(lines.joined(separator: "\n").utf8), account: account)
    }

    public static func read() -> [String] {
        SharedKeychain.get(account: account)
            .map { String(decoding: $0, as: UTF8.self).components(separatedBy: "\n") } ?? []
    }

    public static func clear() {
        SharedKeychain.delete(account: account)
    }
}

/// Optional PIN hand-off from the app to the extension, in case the system shows no PIN UI on iOS.
public enum SharedPin {
    private static let account = "user-pin"

    public static func store(_ pin: String) { SharedKeychain.set(Data(pin.utf8), account: account) }
    public static func load() -> String? { SharedKeychain.get(account: account).map { String(decoding: $0, as: UTF8.self) } }
    public static func clear() { SharedKeychain.delete(account: account) }
}
