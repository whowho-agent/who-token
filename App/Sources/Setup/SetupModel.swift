import Foundation
import Observation
import TokenKit

struct ConnectedToken: Identifiable {
    var id: UInt { info.slot }
    let info: TokenInfo
    /// Valid certificates for client authentication, newest first.
    let certificates: [TokenCertificate]
}

/// Setup for signing in with the USB token in Safari: the token extension (CryptoTokenKit) signs,
/// the Safari extension or this screen supplies the PIN, which iOS never asks for itself.
@MainActor @Observable
final class SetupModel {
    private(set) var token: ConnectedToken?
    private(set) var registeredSerials: [String] = SystemTokenRegistry.registeredSerialNumbers
    private(set) var pinExpiry: Date?
    private(set) var isBusy = false
    private(set) var message: Message?
    private(set) var extensionLog: [String] = []

    struct Message: Equatable {
        let text: String
        let isError: Bool
    }

    private let service: TokenService?
    private let readerMonitor: ReaderMonitor

    init(service: TokenService?, readerMonitor: ReaderMonitor) {
        self.service = service
        self.readerMonitor = readerMonitor
        if service == nil {
            message = Message(text: "Не удалось загрузить библиотеку Рутокен", isError: true)
        }
    }

    var isRegistered: Bool {
        guard let token else { return !registeredSerials.isEmpty }
        return registeredSerials.contains(token.info.serialNumber)
    }

    func start() async {
        guard let service else { return }
        Task {
            for await _ in await readerMonitor.start() { await refresh() }
        }
        Task {
            for await _ in service.slotEvents() { await refresh() }
        }
        await refresh()
    }

    func refresh() async {
        registeredSerials = SystemTokenRegistry.registeredSerialNumbers
        pinExpiry = SharedPin.load() != nil ? SharedPin.expiry : nil
        #if DEBUG
        extensionLog = ExtensionLog.read().reversed()
        #endif
        guard let service else { return }
        do {
            if let info = try await service.tokens().first {
                let certificates = TokenCertificate.usableForClientAuth(try await service.certificates(slot: info.slot))
                token = ConnectedToken(info: info, certificates: certificates)
            } else {
                token = nil
            }
        } catch {
            token = nil
            show("Не удалось прочитать токен: \(error)", isError: true)
        }
    }

    /// Makes the token's certificates available to Safari. Also used after the certificates change.
    func register() async {
        guard let token else { return }
        do {
            SystemTokenRegistry.unregisterAll()
            try SystemTokenRegistry.register(token: token.info, certificates: token.certificates)
            show("Токен подключён к Safari", isError: false)
        } catch {
            show("\(error)", isError: true)
        }
        await refresh()
    }

    func unregister() async {
        SystemTokenRegistry.unregisterAll()
        SharedPin.clear()
        show("Токен отключён от Safari, PIN удалён", isError: false)
        await refresh()
    }

    /// Checks the PIN on the token before sharing it: a wrong PIN tried later by the extension would
    /// cost an attempt each time a site asks for the certificate.
    func savePin(_ pin: String) async {
        guard let service, let token else { return }
        isBusy = true
        defer { isBusy = false }
        do {
            try await service.login(slot: token.info.slot, pin: pin)
            await service.logout(slot: token.info.slot)
            SharedPin.store(pin)
            show("PIN проверен и сохранён на 24 часа", isError: false)
        } catch {
            show("\(error)", isError: true)
        }
        await refresh()
    }

    func forgetPin() async {
        SharedPin.clear()
        show("PIN удалён", isError: false)
        await refresh()
    }

    func clearExtensionLog() {
        ExtensionLog.clear()
        extensionLog = []
    }

    private func show(_ text: String, isError: Bool) {
        message = Message(text: text, isError: isError)
        AppLog.write("[setup] \(text)")
    }
}
