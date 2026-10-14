import CryptoTokenKit
import TokenKit

final class RutokenTokenSession: TKTokenSession, TKTokenSessionDelegate {
    private var rutoken: RutokenToken { token as! RutokenToken }

    func tokenSession(_ session: TKTokenSession, supports operation: TKTokenOperation, keyObjectID: Any, algorithm: TKTokenKeyAlgorithm) -> Bool {
        guard operation == .signData else { return false }
        let supported = Self.match(algorithm) != nil
        ExtensionLog.append("supports \(Self.describe(algorithm)) -> \(supported)")
        return supported
    }

    func tokenSession(_ session: TKTokenSession, sign dataToSign: Data, keyObjectID: Any, algorithm: TKTokenKeyAlgorithm) throws -> Data {
        guard let keyID = keyObjectID as? Data, let (secAlgorithm, digestAlgorithm) = Self.match(algorithm) else {
            throw TKError(.objectNotFound)
        }
        // A PIN handed over by the app lets the extension log in without system UI.
        if rutoken.isLoggedIn() {
            ExtensionLog.append("sign: token already logged in (this extension process)")
        } else if let pin = SharedPin.load() {
            do {
                try rutoken.login(pin: pin)
                ExtensionLog.append("sign: logged in with PIN shared by the app")
            } catch {
                ExtensionLog.append("sign: shared PIN login failed: \(error)")
            }
        } else {
            ExtensionLog.append("sign: not logged in and no shared PIN")
        }
        do {
            let signature = try rutoken.sign(dataToSign, keyID: keyID, algorithm: digestAlgorithm)
            ExtensionLog.append("signed \(secAlgorithm.rawValue), \(dataToSign.count) bytes in")
            return signature
        } catch Pkcs11Error.notLoggedIn {
            ExtensionLog.append("sign: PIN required, asking system for authentication")
            throw TKError(.authenticationNeeded)
        } catch {
            ExtensionLog.append("sign failed: \(error)")
            throw error
        }
    }

    func tokenSession(_ session: TKTokenSession, beginAuthFor operation: TKTokenOperation, constraint: Any) throws -> TKTokenAuthOperation {
        ExtensionLog.append("beginAuth for operation \(operation.rawValue)")
        return PINAuthOperation(token: rutoken)
    }

    /// Prefer what the token does natively (digest PSS / PKCS#1), fall back to raw RSA,
    /// for which Security.framework applies the padding itself.
    private static func match(_ algorithm: TKTokenKeyAlgorithm) -> (SecKeyAlgorithm, DigestSignatureAlgorithm)? {
        for secAlgorithm in DigestSignatureAlgorithm.securityAlgorithms where algorithm.isAlgorithm(secAlgorithm) {
            if let digestAlgorithm = DigestSignatureAlgorithm(secAlgorithm) { return (secAlgorithm, digestAlgorithm) }
        }
        return nil
    }

    private static func describe(_ algorithm: TKTokenKeyAlgorithm) -> String {
        DigestSignatureAlgorithm.securityAlgorithms.first(where: algorithm.isAlgorithm)?.rawValue as String? ?? "other"
    }
}

/// Collects the PIN through the system password UI (if iOS presents one) and logs in on `finish`.
final class PINAuthOperation: TKTokenPasswordAuthOperation {
    private weak var token: RutokenToken?

    init(token: RutokenToken) {
        self.token = token
        super.init()
    }

    required init?(coder: NSCoder) {
        super.init(coder: coder)
    }

    override func finish() throws {
        ExtensionLog.append("auth finish, password provided: \(password?.isEmpty == false)")
        guard let token, let pin = password else { throw TKError(.authenticationFailed) }
        do {
            try token.login(pin: pin)
        } catch {
            ExtensionLog.append("login failed: \(error)")
            throw TKError(.authenticationFailed)
        }
    }
}
