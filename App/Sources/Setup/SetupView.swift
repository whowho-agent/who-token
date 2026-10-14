import SwiftUI
import TokenKit

struct SetupView: View {
    @State var model: SetupModel
    @State private var pin = ""
    @FocusState private var pinFocused: Bool

    var body: some View {
        NavigationStack {
            Form {
                if let message = model.message {
                    Section {
                        Label(message.text, systemImage: message.isError ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                            .foregroundStyle(message.isError ? .red : .green)
                    }
                }
                tokenSection
                safariSection
                pinSection
                instructionsSection
                #if DEBUG
                diagnosticsSection
                #endif
            }
            .navigationTitle("Рутокен для Safari")
            .refreshable { await model.refresh() }
            .overlay { if model.isBusy { ProgressView().controlSize(.large) } }
            .task { await model.start() }
        }
    }

    private var tokenSection: some View {
        Section("Токен") {
            if let token = model.token {
                LabeledContent("Модель", value: token.info.model)
                LabeledContent("Серийный номер", value: token.info.serialNumber)
                if let left = token.info.userPinRetriesLeft, let max = token.info.userPinMaxRetries {
                    LabeledContent("Попыток PIN", value: "\(left) из \(max)")
                }
                if token.certificates.isEmpty {
                    Text("Нет действующих сертификатов для входа").foregroundStyle(.red)
                }
                ForEach(token.certificates) { cert in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(cert.commonName ?? cert.subject).font(.headline)
                        Text(cert.issuer).font(.caption).foregroundStyle(.secondary)
                        Text("до \(cert.notValidAfter.formatted(date: .abbreviated, time: .omitted))").font(.caption)
                    }
                }
            } else {
                Label("Подключите USB-токен Рутокен", systemImage: "cable.connector")
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var safariSection: some View {
        Section {
            if model.isRegistered {
                Label("Сертификат доступен в Safari", systemImage: "checkmark.seal.fill").foregroundStyle(.green)
                Button("Обновить сертификаты", systemImage: "arrow.clockwise") { Task { await model.register() } }
                    .disabled(model.token == nil)
                Button("Отключить от Safari", systemImage: "xmark.circle", role: .destructive) { Task { await model.unregister() } }
            } else {
                Button("Подключить токен к Safari", systemImage: "safari") { Task { await model.register() } }
                    .disabled(model.token?.certificates.isEmpty ?? true)
            }
        } header: {
            Text("Safari")
        } footer: {
            Text("Сайты, запрашивающие сертификат, получат его с токена; подпись выполняется на токене. После замены сертификата нажмите «Обновить сертификаты».")
        }
    }

    private var pinSection: some View {
        Section {
            if let expiry = model.pinExpiry {
                Label("PIN действует до \(expiry.formatted(date: .omitted, time: .shortened))", systemImage: "key.fill")
                    .foregroundStyle(.green)
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
                Button("Проверить и сохранить на 24 часа", action: savePin)
                    .disabled(pin.isEmpty || model.token == nil || model.isBusy)
            }
        } header: {
            Text("PIN")
        } footer: {
            Text("iOS не спрашивает PIN для токена сама. Введите его здесь или кнопкой «Рутокен» в Safari (значок «аА» в адресной строке). PIN хранится на этом устройстве 24 часа и защищён код-паролем.")
        }
    }

    private var instructionsSection: some View {
        Section("Первая настройка") {
            Step(number: 1, text: "Подключите токен и нажмите «Подключить токен к Safari».")
            Step(number: 2, text: "Настройки → Приложения → Safari → Расширения → «Рутокен»: включите и разрешите на нужных сайтах.")
            Step(number: 3, text: "Если сайты организации используют собственный корневой сертификат, установите его профилем и включите в Настройки → Основные → Об этом устройстве → Доверие сертификатам.")
            Step(number: 4, text: "Введите PIN здесь или в расширении «Рутокен» и откройте сайт в Safari. Если Safari пишет, что не может установить безопасное соединение, — введите PIN и обновите страницу.")
        }
    }

    #if DEBUG
    private var diagnosticsSection: some View {
        Section("Журнал расширений") {
            if model.extensionLog.isEmpty {
                Text("Пусто").foregroundStyle(.secondary)
            }
            ForEach(Array(model.extensionLog.prefix(50).enumerated()), id: \.offset) { _, line in
                Text(line).font(.system(size: 11, design: .monospaced))
            }
            Button("Очистить журнал") { model.clearExtensionLog() }
        }
    }
    #endif

    private func savePin() {
        guard !pin.isEmpty else { return }
        let value = pin
        pin = ""
        pinFocused = false
        Task { await model.savePin(value) }
    }
}

private struct Step: View {
    let number: Int
    let text: String

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text("\(number)").font(.headline).foregroundStyle(.tint)
            Text(text)
        }
    }
}
