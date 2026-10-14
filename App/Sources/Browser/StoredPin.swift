import Foundation
import LocalAuthentication
import Security

/// The token PIN kept in the Keychain behind Face ID for a limited time, so after reconnecting the token
/// (or after the token drops the login) the user only looks at the phone instead of typing the PIN.
///
/// One entry at most, bound to the token serial number. The secret is readable only on this device, only
/// while a passcode is set and only with the currently enrolled biometrics (re-enrolling Face ID drops it).
/// The expiry and the serial are plain attributes, so they can be checked without a Face ID prompt.
struct StoredPin: Sendable {
    static let lifetime: TimeInterval = 24 * 60 * 60

    enum ReadResult: Sendable {
        case pin(String)
        /// Nothing usable stored (none, other token, expired or invalidated).
        case none
        /// The user dismissed Face ID or chose to type the PIN.
        case cancelled
        /// Face ID unavailable or locked out, or a Keychain error.
        case unavailable(String)
    }

    private let service = "token-pin"
    /// The app's own keychain group: the default one would be the first entitled group, which is
    /// shared with the token extension. The application identifier is always an allowed group.
    private let accessGroup: String? = (Bundle.main.object(forInfoDictionaryKey: "RBSharedKeychainGroup") as? String)
        .flatMap { $0.hasSuffix(".shared") ? String($0.dropLast(".shared".count)) : nil }

    /// Saves the PIN for `serial` until `now + lifetime`, replacing any previous entry.
    func save(_ pin: String, serial: String, now: Date = .now) throws {
        // Without enrolled biometrics the item could never be read back.
        var error: NSError?
        guard LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            throw StoredPinError.biometryUnavailable(error?.localizedDescription ?? "")
        }
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, .biometryCurrentSet, &accessError
        ) else {
            throw StoredPinError.keychain(accessError.map { String(describing: $0.takeRetainedValue()) } ?? "SecAccessControl")
        }
        delete()
        var item = baseQuery()
        item[kSecAttrAccount] = serial
        item[kSecAttrAccessControl] = access
        item[kSecValueData] = Data(pin.utf8)
        let status = SecItemAdd(item as CFDictionary, nil)
        guard status == errSecSuccess else { throw StoredPinError.keychain(Self.describe(status)) }
        UserDefaults.standard.set(now.addingTimeInterval(Self.lifetime), forKey: Self.expiryKey)
        UserDefaults.standard.set(serial, forKey: Self.serialKey)
    }

    // The expiry is kept outside the keychain item: iOS refuses even attribute-only queries on a
    // biometry-protected item without authentication, so checking it there would always prompt or fail.
    // It is not secret; the PIN itself stays in the keychain behind Face ID.
    private static let expiryKey = "storedPin.expiry"
    private static let serialKey = "storedPin.serial"

    /// Returns the PIN for `serial` after a Face ID prompt with `reason`. Expired entries are deleted
    /// without prompting.
    func read(serial: String, reason: String, now: Date = .now) async -> ReadResult {
        guard let expiry = expiry(serial: serial) else { return .none }
        guard expiry > now else {
            delete()
            return .none
        }

        // Authenticate first (async, does not block a thread), then read the item with the same context.
        let context = LAContext()
        context.localizedFallbackTitle = "Ввести PIN"
        do {
            guard try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) else {
                return .cancelled
            }
        } catch let error as LAError where [.userCancel, .userFallback, .systemCancel, .appCancel].contains(error.code) {
            return .cancelled
        } catch {
            return .unavailable(error.localizedDescription)
        }

        var query = baseQuery()
        query[kSecAttrAccount] = serial
        query[kSecReturnData] = true
        query[kSecMatchLimit] = kSecMatchLimitOne
        query[kSecUseAuthenticationContext] = context
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data, let pin = String(data: data, encoding: .utf8) else {
                delete()
                return .none
            }
            return .pin(pin)
        case errSecUserCanceled:
            return .cancelled
        case errSecItemNotFound, errSecAuthFailed:
            // Biometrics changed since saving: the item can never be read again.
            delete()
            return .none
        default:
            return .unavailable(Self.describe(status))
        }
    }

    /// Expiry of the entry for `serial` (no Face ID prompt).
    func expiry(serial: String) -> Date? {
        guard UserDefaults.standard.string(forKey: Self.serialKey) == serial else { return nil }
        return UserDefaults.standard.object(forKey: Self.expiryKey) as? Date
    }

    /// Removes the stored PIN of any token.
    func delete() {
        SecItemDelete(baseQuery() as CFDictionary)
        UserDefaults.standard.removeObject(forKey: Self.expiryKey)
        UserDefaults.standard.removeObject(forKey: Self.serialKey)
    }

    private func baseQuery() -> [CFString: Any] {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrSynchronizable: false,
            kSecUseDataProtectionKeychain: true,
        ]
        if let accessGroup { query[kSecAttrAccessGroup] = accessGroup }
        return query
    }

    private static func describe(_ status: OSStatus) -> String {
        (SecCopyErrorMessageString(status, nil) as String?) ?? "OSStatus \(status)"
    }
}

enum StoredPinError: Error, CustomStringConvertible {
    case biometryUnavailable(String)
    case keychain(String)

    var description: String {
        switch self {
        case .biometryUnavailable(let reason): "Face ID недоступен: \(reason)"
        case .keychain(let reason): "Keychain: \(reason)"
        }
    }
}
