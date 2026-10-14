import Foundation
import Observation
import ProxyKit
import TokenKit

struct TokenEntry: Identifiable {
    var id: UInt { info.slot }
    let info: TokenInfo
    let certificates: [TokenCertificate]
    let usable: Set<TokenCertificate>
    let algorithms: [SignatureAlgorithm]
}

struct LogLine: Identifiable {
    enum Level { case info, success, failure }
    let id = UUID()
    let date = Date()
    let level: Level
    let text: String
}

/// Stage 1 spike: verifies that the token is reachable on iPhone (USB-C / BT / NFC),
/// certificates are readable and the token signs with the algorithms TLS needs.
@MainActor @Observable
final class TokenLabModel {
    private(set) var readers: [Reader] = []
    private(set) var tokens: [TokenEntry] = []
    private(set) var log: [LogLine] = []
    private(set) var isBusy = false
    var algorithm: SignatureAlgorithm = .rsaPssRsaeSha256
    var mtlsURL = UserDefaults.standard.string(forKey: "mtlsURL") ?? "https://" {
        didSet { UserDefaults.standard.set(mtlsURL, forKey: "mtlsURL") }
    }
    var tlsVersion: TLSVersionChoice = .automatic
    private(set) var lastResponse: String?
    private(set) var registeredSerials: [String] = SystemTokenRegistry.registeredSerialNumbers
    private(set) var extensionLog: [String] = []
    var webTestURL: URL?

    private let service: TokenService?
    private let prompter: PinPrompter
    private let readerMonitor: ReaderMonitor

    init(service: TokenService?, prompter: PinPrompter, readerMonitor: ReaderMonitor) {
        self.service = service
        self.prompter = prompter
        self.readerMonitor = readerMonitor
        if service == nil {
            log.append(LogLine(level: .failure, text: "PKCS#11 не инициализирован"))
        }
    }

    var hasNfcReader: Bool { readers.contains { $0.kind == .nfc } }

    func start() async {
        guard let service else { return }
        Task {
            for await list in await readerMonitor.start() {
                readers = list
                append(.info, "Ридеры: \(list.map { "\($0.name) (\($0.kind))" }.joined(separator: ", "))")
            }
        }
        Task {
            for await slot in service.slotEvents() {
                append(.info, "Событие слота \(slot)")
                await refresh()
            }
        }
        await refresh()
        reloadExtensionLog()
    }

    func refresh() async {
        guard let service else { return }
        do {
            var entries: [TokenEntry] = []
            for info in try await service.tokens() {
                let certificates = try await service.certificates(slot: info.slot)
                entries.append(TokenEntry(
                    info: info,
                    certificates: certificates,
                    usable: Set(TokenCertificate.usableForClientAuth(certificates)),
                    algorithms: try await service.supportedAlgorithms(slot: info.slot)
                ))
            }
            tokens = entries
        } catch {
            append(.failure, "Чтение токенов: \(error)")
        }
    }

    /// USB-C / Bluetooth: the token is already a PKCS#11 slot.
    func testSign(slot: UInt) async {
        guard let service, let entry = tokens.first(where: { $0.info.slot == slot }) else { return }
        await run {
            try await self.loginIfNeeded(service: service, info: entry.info)
            try await self.signAll(service: service, slot: slot, certificates: entry.usable)
        }
    }

    /// NFC: PIN is asked before the tap, so the whole exchange fits into one NFC session.
    func testSignOverNfc() async {
        guard let service else { return }
        guard let pin = await askPin(PinRequest(tokenLabel: "Рутокен NFC", retriesLeft: nil)) else { return }
        let algorithm = algorithm
        await run {
            let start = ContinuousClock.now
            let lines = try await self.readerMonitor.withNfcExchange {
                let slot = try await service.waitForToken()
                try await service.login(slot: slot, pin: pin)
                defer { Task { await service.logout(slot: slot) } }
                let usable = TokenCertificate.usableForClientAuth(try await service.certificates(slot: slot))
                var lines: [String] = []
                for cert in usable {
                    let message = Data("NFC self-test \(Date())".utf8)
                    let signature = try await service.sign(message, keyID: cert.keyID, algorithm: algorithm, slot: slot)
                    let ok = cert.verify(signature: signature, of: message, algorithm: algorithm)
                    lines.append("\(cert.commonName ?? cert.label): \(algorithm.rawValue) \(ok ? "OK" : "ОШИБКА проверки")")
                }
                return lines.isEmpty ? ["На карте нет годных сертификатов"] : lines
            }
            lines.forEach { self.append(.success, "NFC \($0)") }
            self.append(.info, "NFC-обмен занял \((ContinuousClock.now - start).formatted(.units(allowed: [.seconds, .milliseconds])))")
        }
    }

    /// Stage 2 spike: HTTPS GET where the TLS handshake is signed by the token key.
    func testMTLS() async {
        guard let service,
              let entry = tokens.first(where: { !$0.usable.isEmpty }),
              let certificate = TokenCertificate.usableForClientAuth(entry.certificates).first else {
            append(.failure, "Нет токена с годным для mTLS сертификатом")
            return
        }
        guard let url = URL(string: mtlsURL.trimmingCharacters(in: .whitespaces)) else {
            append(.failure, "Некорректный адрес")
            return
        }
        let version = tlsVersion
        await run {
            try await self.loginIfNeeded(service: service, info: entry.info)
            let key = TokenPrivateKey(
                service: service, slot: entry.info.slot, keyID: certificate.keyID, supported: entry.algorithms
            ) { algorithm, elapsed in
                Task { @MainActor in
                    self.append(.info, "Токен подписал CertificateVerify: \(algorithm.rawValue), \(elapsed.formatted(.units(allowed: [.milliseconds])))")
                }
            }
            let response = try await MTLSClient.get(
                url, certificate: certificate, privateKey: key, extraTrustRootsPEM: Self.standCA, version: version
            )
            self.lastResponse = response.body
            self.append(.success, "\(response.tlsVersion): \(response.statusLine), \(response.elapsed.formatted(.units(allowed: [.milliseconds])))")
        }
    }

    // MARK: - Variant B: CryptoTokenKit extension + plain WKWebView

    func registerInSystem() {
        guard let entry = tokens.first(where: { !$0.usable.isEmpty }) else {
            append(.failure, "Нет токена с годным для mTLS сертификатом")
            return
        }
        do {
            try SystemTokenRegistry.register(token: entry.info, certificates: Array(entry.usable))
            registeredSerials = SystemTokenRegistry.registeredSerialNumbers
            append(.success, "Зарегистрировано в системе: \(entry.usable.count) серт., удостоверений в keychain: \(SystemTokenRegistry.identities().count)")
            reloadExtensionLog()
        } catch {
            append(.failure, "Регистрация: \(error)")
        }
    }

    func unregisterFromSystem() {
        SystemTokenRegistry.unregisterAll()
        registeredSerials = SystemTokenRegistry.registeredSerialNumbers
        append(.info, "Регистрация в системе удалена")
    }

    /// Fallback if iOS shows no PIN UI for the extension: hand the PIN over via the shared keychain.
    func sharePinWithExtension() async {
        guard let pin = await askPin(PinRequest(tokenLabel: "PIN для расширения", retriesLeft: nil)) else { return }
        SharedPin.store(pin)
        append(.info, "PIN передан расширению (общий keychain)")
    }

    func forgetSharedPin() {
        SharedPin.clear()
        append(.info, "PIN для расширения удалён")
    }

    func openWebTest() {
        guard let url = URL(string: mtlsURL.trimmingCharacters(in: .whitespaces)) else { return }
        ExtensionLog.clear()
        webTestURL = url
    }

    func reloadExtensionLog() {
        extensionLog = ExtensionLog.read().reversed()
        AppLog.write("[keychain]\n" + SystemTokenRegistry.diagnostics())
        AppLog.write("[extension log]\n" + ExtensionLog.read().joined(separator: "\n"))
    }

    var standTrustRoots: [Data] { Self.standCA }

    func appendFromWebView(_ text: String) {
        append(.info, text)
    }

    /// CA of the local test stand (stand/run-stand.sh copies it into the app bundle).
    private static let standCA: [Data] = Bundle.main.url(forResource: "stand-ca", withExtension: "pem")
        .flatMap { try? Data(contentsOf: $0) }
        .map { [$0] } ?? []

    // MARK: - Private

    private func loginIfNeeded(service: TokenService, info: TokenInfo) async throws {
        guard await !service.isLoggedIn(slot: info.slot) else { return }
        var retriesLeft = info.userPinRetriesLeft
        while true {
            guard let pin = await askPin(PinRequest(tokenLabel: info.label, retriesLeft: retriesLeft)) else {
                throw CancellationError()
            }
            do {
                try await service.login(slot: info.slot, pin: pin)
                return
            } catch Pkcs11Error.pinIncorrect(let left) {
                append(.failure, Pkcs11Error.pinIncorrect(retriesLeft: left).description)
                retriesLeft = left
            }
        }
    }

    private func signAll(service: TokenService, slot: UInt, certificates: Set<TokenCertificate>) async throws {
        guard !certificates.isEmpty else {
            append(.failure, "Нет годных для mTLS сертификатов")
            return
        }
        for cert in certificates {
            let message = Data("TokenLab self-test \(Date())".utf8)
            let start = ContinuousClock.now
            let signature = try await service.sign(message, keyID: cert.keyID, algorithm: algorithm, slot: slot)
            let elapsed = (ContinuousClock.now - start).formatted(.units(allowed: [.milliseconds]))
            if cert.verify(signature: signature, of: message, algorithm: algorithm) {
                append(.success, "\(cert.commonName ?? cert.label): \(algorithm.rawValue), \(signature.count * 8) бит, \(elapsed) — подпись верна")
            } else {
                append(.failure, "\(cert.commonName ?? cert.label): \(algorithm.rawValue) — подпись НЕ прошла проверку")
            }
        }
    }

    private func askPin(_ request: PinRequest) async -> String? {
        await prompter.ask(request)
    }

    private func run(_ operation: @escaping () async throws -> Void) async {
        isBusy = true
        defer { isBusy = false }
        do {
            try await operation()
        } catch is CancellationError {
            append(.info, "Отменено")
        } catch {
            append(.failure, String(describing: error))
        }
        await refresh()
    }

    private func append(_ level: LogLine.Level, _ text: String) {
        log.insert(LogLine(level: level, text: text), at: 0)
        AppLog.write("[app] \(text)")
    }
}
