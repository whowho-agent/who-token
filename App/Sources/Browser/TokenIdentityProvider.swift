import Foundation
import ProxyKit
import TokenKit

/// Gives the proxy the client identity from the connected Rutoken. The PIN is asked lazily, on the first
/// signature, and only once even when WebKit opens several connections at the same time.
/// After a typed PIN works it is kept for 24 hours behind Face ID (`StoredPin`), so a later login needs
/// only a glance.
actor TokenIdentityProvider: ClientIdentityProvider {
    private let service: TokenService
    private let prompter: PinPrompter
    private let onStatus: @Sendable (IdentityStatus) -> Void
    private let storedPin = StoredPin()
    private var login: Task<Void, Error>?

    init(service: TokenService, prompter: PinPrompter, onStatus: @escaping @Sendable (IdentityStatus) -> Void = { _ in }) {
        self.service = service
        self.prompter = prompter
        self.onStatus = onStatus
    }

    /// Logs out of the token and forgets any stored PIN ("Сбросить вход на токен" in settings).
    func forgetLogin() async {
        storedPin.delete()
        for token in (try? await service.tokens()) ?? [] {
            await service.logout(slot: token.slot)
        }
        AppLog.write("[identity] вход на токен сброшен, сохранённый PIN удалён")
    }

    func identity(for host: String) async throws -> ClientIdentity? {
        // Right after launch or plug-in the token may take a moment to show up as a slot.
        var token = try await service.tokens().first
        if token == nil, let slot = try? await service.waitForToken(timeout: .seconds(3)) {
            token = try? await service.tokenInfo(slot: slot)
        }
        guard let token else {
            AppLog.write("[identity] \(host): токен не подключён, соединение без сертификата")
            onStatus(.tokenMissing(host: host))
            return nil
        }
        let certificates = TokenCertificate.usableForClientAuth(try await service.certificates(slot: token.slot))
        guard let certificate = certificates.first else {
            AppLog.write("[identity] \(host): нет годных сертификатов")
            onStatus(.noCertificate(host: host))
            return nil
        }
        // No PIN yet: the certificate is public. The PIN is asked only if the server actually
        // requests client authentication, i.e. when the TLS handshake needs a signature.
        let slot = token.slot
        let keyID = certificate.keyID
        let key = TokenPrivateKey(
            slot: slot, keyID: keyID,
            supported: try await service.supportedAlgorithms(slot: slot),
            onSign: { algorithm, elapsed in
                AppLog.write("[token] \(host): подпись \(algorithm.rawValue) \(elapsed.formatted(.units(allowed: [.milliseconds])))")
            },
            signer: { [service] message, algorithm in
                do {
                    return try await service.sign(message, keyID: keyID, algorithm: algorithm, slot: slot)
                } catch Pkcs11Error.notLoggedIn {
                    AppLog.write("[identity] \(host) запросил клиентский сертификат, нужен PIN")
                    try await self.ensureLoggedIn(token, host: host)
                    return try await service.sign(message, keyID: keyID, algorithm: algorithm, slot: slot)
                }
            }
        )
        let intermediates = Self.intermediates(for: certificate)
        AppLog.write("[identity] \(host): сертификат \(certificate.commonName ?? certificate.label), промежуточных CA в цепочке: \(intermediates.count)")
        return ClientIdentity(certificate: certificate, intermediates: intermediates, privateKey: key)
    }

    /// Servers such as AD FS need the issuing CA too, but the token holds only the leaf.
    /// Intermediate CA certificates are bundled in App/ClientChain (public certificates).
    private static func intermediates(for certificate: TokenCertificate) -> [Data] {
        bundledCAs.filter { $0.subject == certificate.issuer }.map(\.der)
    }

    private static let bundledCAs: [TokenCertificate] = (Bundle.main.urls(forResourcesWithExtension: "pem", subdirectory: "ClientChain") ?? [])
        .compactMap { try? Data(contentsOf: $0) }
        .compactMap { pem in
            let base64 = String(decoding: pem, as: UTF8.self).components(separatedBy: "\n").filter { !$0.hasPrefix("-----") }.joined()
            return Data(base64Encoded: base64).flatMap { try? TokenCertificate(keyID: Data(), label: "", der: $0) }
        }

    /// Logs in once for all concurrent signers; every waiting host gets its own status on failure.
    private func ensureLoggedIn(_ token: TokenInfo, host: String) async throws {
        if await service.isLoggedIn(slot: token.slot) { return }
        do {
            if let login {
                try await login.value
            } else {
                let task = Task { try await self.logIn(token) }
                login = task
                defer { login = nil }
                try await task.value
            }
        } catch is CancellationError {
            onStatus(.pinCancelled(host: host))
            throw CancellationError()
        } catch {
            onStatus(.loginFailed(host: host, reason: String(describing: error)))
            throw error
        }
    }

    private func logIn(_ token: TokenInfo) async throws {
        var retriesLeft = token.userPinRetriesLeft
        switch await storedPin.read(serial: token.serialNumber, reason: "Вход на токен \(token.label)") {
        case .pin(let pin):
            do {
                try await service.login(slot: token.slot, pin: pin)
                AppLog.write("[identity] вход на токен по сохранённому PIN (Face ID)")
                onStatus(.signedIn)
                return
            } catch Pkcs11Error.pinIncorrect(let left) {
                // Never try a stored PIN twice: the token locks after a few wrong attempts.
                storedPin.delete()
                retriesLeft = left
                AppLog.write("[identity] сохранённый PIN не подошёл и удалён, осталось попыток: \(left.map(String.init) ?? "?")")
            }
        case .cancelled:
            AppLog.write("[identity] Face ID отменён, спрашиваем PIN")
        case .unavailable(let reason):
            AppLog.write("[identity] сохранённый PIN недоступен (\(reason)), спрашиваем PIN")
        case .none:
            AppLog.write("[identity] сохранённого PIN нет или срок истёк, спрашиваем PIN")
        }
        try await promptAndLogin(token, retriesLeft: retriesLeft)
    }

    private func promptAndLogin(_ token: TokenInfo, retriesLeft: Int?) async throws {
        var retriesLeft = retriesLeft
        while true {
            guard let pin = await prompter.ask(PinRequest(tokenLabel: token.label, retriesLeft: retriesLeft)) else {
                throw CancellationError()
            }
            do {
                try await service.login(slot: token.slot, pin: pin)
                AppLog.write("[identity] вход на токен выполнен")
                onStatus(.signedIn)
                remember(pin, token: token)
                return
            } catch Pkcs11Error.pinIncorrect(let left) {
                retriesLeft = left
            }
        }
    }

    private func remember(_ pin: String, token: TokenInfo) {
        do {
            try storedPin.save(pin, serial: token.serialNumber)
            AppLog.write("[identity] PIN сохранён в Keychain под Face ID на 24 ч")
        } catch {
            AppLog.write("[identity] PIN не сохранён: \(error)")
        }
    }
}
