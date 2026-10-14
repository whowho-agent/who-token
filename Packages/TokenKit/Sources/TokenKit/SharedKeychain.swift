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

/// PIN hand-off to the CryptoTokenKit extension, which has no UI of its own and gets no PIN prompt
/// from iOS. Entered in the app or in the Safari extension popup; valid for a limited time.
/// Protected by the device lock only (the token extension can't show Face ID).
public enum SharedPin {
    private static let account = "user-pin"
    private static let expiryAccount = "user-pin-expiry"
    public static let lifetime: TimeInterval = 24 * 3600

    public static func store(_ pin: String, now: Date = .now) {
        SharedKeychain.set(Data(pin.utf8), account: account)
        SharedKeychain.set(Data(String(now.addingTimeInterval(lifetime).timeIntervalSince1970).utf8), account: expiryAccount)
    }

    /// The PIN if one was handed over and hasn't expired; an expired one is deleted.
    public static func load(now: Date = .now) -> String? {
        guard let expiry = expiry, expiry > now else {
            clear()
            return nil
        }
        return SharedKeychain.get(account: account).map { String(decoding: $0, as: UTF8.self) }
    }

    public static var expiry: Date? {
        SharedKeychain.get(account: expiryAccount)
            .flatMap { TimeInterval(String(decoding: $0, as: UTF8.self)) }
            .map(Date.init(timeIntervalSince1970:))
    }

    public static func clear() {
        SharedKeychain.delete(account: account)
        SharedKeychain.delete(account: expiryAccount)
    }
}
