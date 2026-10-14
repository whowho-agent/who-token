import CPkcs11

public enum Pkcs11Error: Error, Equatable, Sendable {
    /// Wrong user PIN; `retriesLeft` is nil when the token does not report it.
    case pinIncorrect(retriesLeft: Int?)
    case pinLocked
    case notLoggedIn
    case tokenNotPresent
    case keyNotFound
    case mechanismNotSupported
    case function(String, rv: CK_RV)

    static func check(_ rv: CK_RV, _ function: String) throws {
        guard rv != CKR_OK else { return }
        switch rv {
        case CKR_PIN_LOCKED: throw Pkcs11Error.pinLocked
        case CKR_USER_NOT_LOGGED_IN: throw Pkcs11Error.notLoggedIn
        case CKR_TOKEN_NOT_PRESENT, CKR_DEVICE_REMOVED, CKR_SESSION_HANDLE_INVALID: throw Pkcs11Error.tokenNotPresent
        case CKR_MECHANISM_INVALID: throw Pkcs11Error.mechanismNotSupported
        default: throw Pkcs11Error.function(function, rv: rv)
        }
    }
}

extension Pkcs11Error: CustomStringConvertible {
    public var description: String {
        switch self {
        case .pinIncorrect(let left?): "Неверный PIN, осталось попыток: \(left)"
        case .pinIncorrect: "Неверный PIN"
        case .pinLocked: "PIN заблокирован"
        case .notLoggedIn: "Требуется ввод PIN"
        case .tokenNotPresent: "Токен отключён"
        case .keyNotFound: "Закрытый ключ для сертификата не найден"
        case .mechanismNotSupported: "Механизм подписи не поддерживается токеном"
        case .function(let name, let rv): "\(name) вернула 0x\(String(rv, radix: 16))"
        }
    }
}
