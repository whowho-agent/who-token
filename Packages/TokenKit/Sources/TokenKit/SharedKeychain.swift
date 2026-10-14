import Foundation
import Security

/// Small keychain store shared by the app and its extensions.
public enum SharedKeychain {
    /// The shared access group. Discovered at run time rather than taken from Info.plist, because
    /// re-signing (Sideloadly, another team) changes the team prefix in the entitlements: iOS puts a new
    /// item into the first `keychain-access-groups` entry, which is the shared group in all three targets.
    public static let accessGroup: String? = discoverAccessGroup()
        ?? Bundle.main.object(forInfoDictionaryKey: "RBSharedKeychainGroup") as? String

    private static func discoverAccessGroup() -> String? {
        let probe: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: "RutokenBrowser.group-probe",
            kSecAttrAccount: "probe",
            kSecUseDataProtectionKeychain: true
        ]
        var query = probe
        query[kSecReturnAttributes] = true
        var result: CFTypeRef?
        var status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            var item = probe
            item[kSecAttrAccessible] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            item[kSecReturnAttributes] = true
            status = SecItemAdd(item as CFDictionary, &result)
        }
        guard status == errSecSuccess else { return nil }
        return (result as? [CFString: Any])?[kSecAttrAccessGroup] as? String
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

/// Diagnostics: the extensions run in their own processes, so they leave a short event log
/// in the shared keychain for the app to display.
public enum ExtensionLog {
    private static let account = "extension-log"

    /// Debug builds only: Release writes nothing (lines may contain host names and token state).
    public static func append(_ line: @autoclosure () -> String) {
        #if DEBUG
        let line = line()
        // Safari retries a failed signature dozens of times per second; keep one line per message run.
        if let last = read().last, last.hasSuffix(" " + line) { return }
        let stamp = Date().formatted(date: .omitted, time: .standard)
        let lines = (read() + ["\(stamp) \(line)"]).suffix(300)
        SharedKeychain.set(Data(lines.joined(separator: "\n").utf8), account: account)
        #endif
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

    // MARK: Last problem, for hints in Safari

    private static let failureAccount = "user-pin-failure"

    /// The token extension records why it couldn't sign (wrong PIN, token not connected) so the Safari
    /// extension can explain the failed page load to the user.
    public static func recordFailure(_ text: String, now: Date = .now) {
        SharedKeychain.set(Data("\(now.timeIntervalSince1970)|\(text)".utf8), account: failureAccount)
    }

    public static var lastFailure: (text: String, date: Date)? {
        guard let raw = SharedKeychain.get(account: failureAccount).map({ String(decoding: $0, as: UTF8.self) }),
              let bar = raw.firstIndex(of: "|"), let seconds = TimeInterval(raw[..<bar]) else { return nil }
        return (String(raw[raw.index(after: bar)...]), Date(timeIntervalSince1970: seconds))
    }

    public static func clearFailure() {
        SharedKeychain.delete(account: failureAccount)
    }
}

/// What the Safari extension reports about itself (the app can't query site access on its own).
public enum SafariExtensionReport {
    private static let account = "safari-extension-report"

    public struct Report: Sendable {
        public let date: Date
        /// The extension may read pages on all https sites, needed to notice failed sign-ins.
        public let allSitesAllowed: Bool
    }

    public static func store(allSitesAllowed: Bool, now: Date = .now) {
        SharedKeychain.set(Data("\(now.timeIntervalSince1970)|\(allSitesAllowed ? 1 : 0)".utf8), account: account)
    }

    public static var latest: Report? {
        guard let raw = SharedKeychain.get(account: account).map({ String(decoding: $0, as: UTF8.self) }) else { return nil }
        let parts = raw.split(separator: "|")
        guard parts.count == 2, let seconds = TimeInterval(parts[0]) else { return nil }
        return Report(date: Date(timeIntervalSince1970: seconds), allSitesAllowed: parts[1] == "1")
    }
}
