import SwiftUI
import TokenKit

struct SetupView: View {
    @State var model: SetupModel
    @State private var pin = ""
    @FocusState private var pinFocused: Bool
    /// Site whose root certificate to look up: the work site, or a `rutoken://root?site=` URL from the
    /// Safari extension.
    @State private var rootSite: RootSite?
    @State private var showsSites = false
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        NavigationStack {
            List {
                Section { SetupHeader(remaining: ReadinessSection.remaining(model)) }
                ReadinessSection(model: model,
                                 openRootCertificate: { rootSite = RootSite(address: model.workSite) },
                                 openSites: { showsSites = true })
                pinSection
                Section {
                    NavigationLink("Токен и сертификаты") { TokenDetailView(model: model) }
                    #if DEBUG
                    NavigationLink("Журнал расширений") { ExtensionLogView(model: model) }
                    #endif
                }
            }
            .listStyle(.insetGrouped)
            .navigationTitle("Рутокен")
            .navigationBarTitleDisplayMode(.inline)
            .refreshable { await model.refresh() }
            .task { await model.start() }
            // Coming back from Settings (extension switched on, profile installed): re-check.
            .onChange(of: scenePhase) { _, phase in
                if phase == .active { Task { await model.refresh() } }
            }
            .navigationDestination(item: $rootSite) { site in
                RootCertificateView(model: RootCertificateModel(address: site.address))
                    .onDisappear { Task { await model.workSiteChanged() } }
            }
            .sheet(isPresented: $model.showsTrustGuide, onDismiss: model.dismissTrustGuide) {
                TrustGuideView(site: model.workSite, rootName: TrustGuide.rootName)
            }
            .navigationDestination(isPresented: $showsSites) { SitesView(model: model) }
            .onOpenURL { url in
                // rutoken://root?site=wiki.example.com — opened by the Safari extension.
                guard url.scheme == "rutoken", url.host() == "root" else { return }
                let site = URLComponents(url: url, resolvingAgainstBaseURL: false)?
                    .queryItems?.first { $0.name == "site" }?.value ?? ""
                rootSite = RootSite(address: site)
            }
            .alert("Не получилось", isPresented: errorShown, presenting: model.message) { _ in
                Button("OK") { model.clearMessage() }
            } message: { message in
                Text(message.text)
            }
        }
    }

    private var errorShown: Binding<Bool> {
        Binding(get: { model.message?.isError == true }, set: { if !$0 { model.clearMessage() } })
    }

    private var pinSection: some View {
        Section {
            if let expiry = model.pinExpiry {
                LabeledContent("Действует до", value: expiry.formatted(date: .omitted, time: .shortened))
                Button("Забыть PIN", role: .destructive) { Task { await model.forgetPin() } }
            } else {
                // Rutoken PINs may contain letters, so a full ASCII keyboard is required.
                SecureField("PIN пользователя", text: $pin)
                    .keyboardType(.asciiCapable)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .focused($pinFocused)
                    .submitLabel(.done)
                    .onSubmit(savePin)
                Button(action: savePin) {
                    if model.isBusy { ProgressView() } else { Text("Сохранить на 24 часа") }
                }
                .disabled(pin.isEmpty || model.token == nil || model.isBusy)
            }
        } header: {
            Text("PIN")
        } footer: {
            Text("PIN также можно ввести кнопкой «Рутокен» в Safari. Он хранится только на этом iPhone.")
        }
    }

    private func savePin() {
        guard !pin.isEmpty else { return }
        let value = pin
        pin = ""
        pinFocused = false
        Task { await model.savePin(value) }
    }
}

/// Token details and its registration in Safari.
private struct TokenDetailView: View {
    @Bindable var model: SetupModel

    var body: some View {
        List {
            if let token = model.token {
                Section("Токен") {
                    LabeledContent("Модель", value: token.info.model)
                    LabeledContent("Серийный номер", value: token.info.serialNumber)
                    if let left = token.info.userPinRetriesLeft, let max = token.info.userPinMaxRetries {
                        LabeledContent("Попыток PIN", value: "\(left) из \(max)")
                    }
                }
                Section("Сертификаты") {
                    if token.certificates.isEmpty {
                        Text("Нет действующих сертификатов для входа").foregroundStyle(.secondary)
                    }
                    ForEach(token.certificates) { cert in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(cert.commonName ?? cert.subject)
                            Text("до \(cert.notValidAfter.formatted(date: .abbreviated, time: .omitted)) · \(cert.issuer)")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                                .lineLimit(2)
                        }
                    }
                }
            } else {
                Section {
                    ContentUnavailableView("Токен не подключён", systemImage: "cable.connector",
                                           description: Text("Вставьте USB-токен Рутокен."))
                }
            }
            Section {
                Button(model.isRegistered ? "Обновить сертификаты в Safari" : "Подключить к Safari") {
                    Task { await model.register() }
                }
                .disabled(model.token?.certificates.isEmpty ?? true)
                if model.isRegistered {
                    Button("Отключить от Safari", role: .destructive) { Task { await model.unregister() } }
                }
            } footer: {
                Text("После замены сертификата на токене нажмите «Обновить сертификаты в Safari».")
            }
        }
        .navigationTitle("Токен")
        .navigationBarTitleDisplayMode(.inline)
    }
}

#if DEBUG
private struct ExtensionLogView: View {
    @Bindable var model: SetupModel

    var body: some View {
        List {
            if model.extensionLog.isEmpty {
                Text("Пусто").foregroundStyle(.secondary)
            }
            ForEach(Array(model.extensionLog.prefix(100).enumerated()), id: \.offset) { _, line in
                Text(line).font(.system(size: 11, design: .monospaced))
            }
        }
        .navigationTitle("Журнал")
        .toolbar { Button("Очистить") { model.clearExtensionLog() } }
    }
}
#endif

struct RootSite: Identifiable, Hashable {
    let id = UUID()
    let address: String
}
