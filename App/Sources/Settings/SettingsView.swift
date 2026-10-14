import SwiftUI

/// Browser settings: token hosts, default layout, bundled organization certificates, sign-out actions
/// and the team's diagnostics page.
struct SettingsView: View {
    @Bindable var model: BrowserModel
    @Environment(\.dismiss) private var dismiss
    @State private var certificates: [OrganizationCertificate] = []
    @State private var confirmClear = false
    @State private var busy = false
    @State private var done: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("host1, *.example.com", text: $model.tokenHosts, axis: .vertical)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                } header: {
                    Text("Сайты с входом по токену")
                } footer: {
                    Text("Адреса через запятую; *.домен — все поддомены (но не сам домен). Для этих сайтов сертификат с Рутокена передаётся серверу, PIN-код спрашивается, только если сервер его запросил. Остальные сайты открываются напрямую.")
                }

                Section {
                    Toggle("Версия для компьютера по умолчанию", isOn: $model.desktopMode)
                } footer: {
                    Text("Сайты получают настольную раскладку и User-Agent Safari для Mac — для сайтов, которые уводят iPhone в упрощённый мобильный интерфейс.")
                }

                Section {
                    Button("Сбросить вход на токен", systemImage: "key.slash") {
                        run("Вход на токен сброшен") { await model.forgetTokenLogin() }
                    }
                    Button("Очистить данные сайтов", systemImage: "trash", role: .destructive) { confirmClear = true }
                        .confirmationDialog("Очистить данные сайтов?", isPresented: $confirmClear, titleVisibility: .visible) {
                            Button("Очистить", role: .destructive) {
                                run("Данные сайтов очищены") { await model.clearWebsiteData() }
                            }
                        } message: {
                            Text("Будут удалены cookies, сохранённые входы, кэш и локальные данные всех сайтов.")
                        }
                } header: {
                    Text("Вход")
                } footer: {
                    if let done {
                        Label(done, systemImage: "checkmark.circle").foregroundStyle(.green)
                    } else {
                        Text("Сброс входа на токен: PIN-код спросят заново при следующем входе на сайт. Очистка данных: выход со всех сайтов.")
                    }
                }
                .disabled(busy)

                Section {
                    if certificates.isEmpty {
                        Text("В сборку не добавлены сертификаты организации")
                            .foregroundStyle(.secondary)
                    }
                    ForEach(certificates) { certificate in
                        CertificateRow(certificate: certificate)
                    }
                } header: {
                    Text("Сертификаты организации")
                } footer: {
                    Text("Встроены в приложение при сборке (App/TrustRoots — корневые для проверки серверов, App/ClientChain — промежуточные для цепочки клиентского сертификата).")
                }

                Section {
                    NavigationLink {
                        DiagnosticsView(model: model)
                    } label: {
                        Label("Диагностика", systemImage: "stethoscope")
                    }
                }
            }
            .navigationTitle("Настройки")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Готово") { dismiss() } } }
            .task { certificates = OrganizationCertificate.loadBundled() }
        }
    }

    private func run(_ message: String, _ action: @escaping @MainActor () async -> Void) {
        busy = true
        done = nil
        Task {
            await action()
            busy = false
            done = message
        }
    }
}

private struct CertificateRow: View {
    let certificate: OrganizationCertificate

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(certificate.name)
            Group {
                switch certificate.role {
                case .trustRoot: Text("Корневой, \(certificate.file)")
                case .clientChain: Text("Промежуточный клиентский, \(certificate.file)")
                }
            }
            .font(.caption)
            .foregroundStyle(.secondary)
            if let date = certificate.notValidAfter {
                Text(certificate.isExpired
                     ? "Истёк \(date.formatted(date: .numeric, time: .omitted))"
                     : "Действует до \(date.formatted(date: .numeric, time: .omitted))")
                    .font(.caption)
                    .foregroundStyle(certificate.isExpired ? .red : .secondary)
            }
        }
    }
}

/// Proxy state, WebKit trust-challenge counters and the event log, for checking a site with the team.
struct DiagnosticsView: View {
    let model: BrowserModel

    var body: some View {
        Form {
            Section("Состояние") {
                Text(model.status)
                ForEach(model.trustChallenges.sorted(by: { $0.key < $1.key }), id: \.key) { host, count in
                    LabeledContent(host, value: "проверок сервера: \(count)")
                }
            }
            Section("События") {
                ForEach(Array(model.events.enumerated()), id: \.offset) { _, line in
                    Text(line).font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                }
            }
        }
        .navigationTitle("Диагностика")
        .navigationBarTitleDisplayMode(.inline)
    }
}
