import Foundation
import Observation
import SafariServices
import TokenKit
import UIKit

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

    // MARK: Readiness checklist

    /// nil when unknown (iOS before 26.2 can't tell).
    private(set) var safariExtensionEnabled: Bool?
    private(set) var extensionReport: SafariExtensionReport.Report?
    /// A site of the organization, checked to see whether its root certificate is trusted on this device.
    var workSite = UserDefaults.standard.string(forKey: "workSite") ?? "" {
        didSet { UserDefaults.standard.set(workSite, forKey: "workSite") }
    }
    private(set) var workSiteTrusted: Bool?
    private(set) var isCheckingWorkSite = false

    struct Message: Equatable {
        let text: String
        let isError: Bool
    }

    private var service: TokenService?
    private let readerMonitor: ReaderMonitor

    init(readerMonitor: ReaderMonitor) {
        self.readerMonitor = readerMonitor
    }

    var isRegistered: Bool {
        guard let token else { return !registeredSerials.isEmpty }
        return registeredSerials.contains(token.info.serialNumber)
    }

    func start() async {
        // C_Initialize waits on PC/SC reader discovery; keep it off the main thread so the UI shows at once.
        let service: TokenService
        do {
            service = try await Task.detached { try TokenService() }.value
        } catch {
            message = Message(text: "Не удалось загрузить библиотеку Рутокен: \(error)", isError: true)
            await refreshReadiness()
            return
        }
        self.service = service
        Task {
            for await _ in await readerMonitor.start() { await refresh() }
        }
        Task {
            for await _ in service.slotEvents() { await refresh() }
        }
        await refresh()
    }

    func refresh() async {
        await refreshReadiness()
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
            SharedPin.clearFailure()
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

    func refreshReadiness() async {
        extensionReport = SafariExtensionReport.latest
        if #available(iOS 26.2, *) {
            safariExtensionEnabled = try? await SFSafariExtensionManager.stateOfExtension(withIdentifier: Self.safariExtensionID).isEnabled
        } else {
            // Without the API, a recent report from the extension means it is enabled.
            safariExtensionEnabled = extensionReport.map { _ in true }
        }
        await checkWorkSite()
    }

    func checkWorkSite() async {
        let site = workSite.trimmingCharacters(in: .whitespaces)
        guard !site.isEmpty else {
            workSiteTrusted = nil
            return
        }
        isCheckingWorkSite = true
        defer { isCheckingWorkSite = false }
        workSiteTrusted = try? await RootCertificateFinder.isTrustedBySystem(siteAddress: site)
    }

    /// Opens Settings → Apps → Safari → Extensions → Рутокен (iOS 26.2+), otherwise the app's settings.
    func openSafariExtensionSettings() {
        if #available(iOS 26.2, *) {
            SFSafariSettings.openExtensionsSettings(forIdentifiers: [Self.safariExtensionID]) { error in
                if error != nil { Self.openAppSettings() }
            }
        } else {
            Self.openAppSettings()
        }
    }

    /// Settings → General → About → Certificate Trust Settings. There is no public link; the private
    /// prefs URL works on current iOS versions, otherwise Settings opens at the app.
    func openCertificateTrustSettings() {
        let url = URL(string: "App-prefs:General&path=About/CERT_TRUST_SETTINGS")!
        UIApplication.shared.open(url) { opened in
            if !opened { Self.openAppSettings() }
        }
    }

    private static func openAppSettings() {
        UIApplication.shared.open(URL(string: UIApplication.openSettingsURLString)!)
    }

    /// Read from the embedded extension: re-signing may change bundle ids.
    static let safariExtensionID: String = {
        Bundle.main.builtInPlugInsURL
            .flatMap { Bundle(url: $0.appending(path: "RutokenSafariExtension.appex")) }?
            .bundleIdentifier ?? (Bundle.main.bundleIdentifier ?? "") + ".SafariExtension"
    }()

    func clearMessage() {
        message = nil
    }

    /// The root certificate screen remembers the site it checked as the work site.
    func workSiteChanged() async {
        workSite = UserDefaults.standard.string(forKey: "workSite") ?? workSite
        await checkWorkSite()
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
