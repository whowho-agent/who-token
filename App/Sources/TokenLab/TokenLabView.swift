import ProxyKit
import SwiftUI
import TokenKit

struct TokenLabView: View {
    @State var model: TokenLabModel

    var body: some View {
        NavigationStack {
            List {
                Section("Ридеры") {
                    if model.readers.isEmpty {
                        Text("Нет ридеров").foregroundStyle(.secondary)
                    }
                    ForEach(model.readers) { reader in
                        Label(reader.name, systemImage: icon(for: reader.kind))
                    }
                }

                Section("Алгоритм подписи") {
                    Picker("Алгоритм", selection: $model.algorithm) {
                        ForEach(SignatureAlgorithm.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                    }
                    if model.hasNfcReader {
                        Button("Тестовая подпись по NFC", systemImage: "wave.3.right") {
                            Task { await model.testSignOverNfc() }
                        }
                        .disabled(model.isBusy)
                    }
                }

                Section("mTLS-запрос") {
                    TextField("https://…", text: $model.mtlsURL)
                        .keyboardType(.URL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    Picker("Версия", selection: $model.tlsVersion) {
                        ForEach(TLSVersionChoice.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                    }
                    Button("Выполнить запрос", systemImage: "lock.shield") {
                        Task { await model.testMTLS() }
                    }
                    .disabled(model.isBusy || model.tokens.isEmpty)
                    if let response = model.lastResponse {
                        DisclosureGroup("Ответ сервера") {
                            ScrollView(.horizontal) {
                                Text(response.strippingHTML)
                                    .font(.system(size: 10, design: .monospaced))
                                    .textSelection(.enabled)
                            }
                        }
                    }
                }

                Section {
                    LabeledContent("Зарегистрировано", value: model.registeredSerials.isEmpty ? "нет" : model.registeredSerials.joined(separator: ", "))
                    Button("Зарегистрировать в системе", systemImage: "key.viewfinder") { model.registerInSystem() }
                        .disabled(model.tokens.isEmpty)
                    Button("Открыть адрес в WKWebView", systemImage: "safari") { model.openWebTest() }
                        .disabled(model.registeredSerials.isEmpty)
                    Button("Передать PIN расширению", systemImage: "key.horizontal") { Task { await model.sharePinWithExtension() } }
                    Button("Забыть PIN / удалить регистрацию", systemImage: "trash", role: .destructive) {
                        model.forgetSharedPin()
                        model.unregisterFromSystem()
                    }
                    DisclosureGroup("Журнал расширения") {
                        Button("Обновить") { model.reloadExtensionLog() }
                        ForEach(Array(model.extensionLog.enumerated()), id: \.offset) { _, line in
                            Text(line).font(.system(size: 11, design: .monospaced))
                        }
                    }
                } header: {
                    Text("Вариант B: CryptoTokenKit")
                } footer: {
                    Text("WKWebView без прокси: сертификат берётся из системы, подпись делает расширение через токен. Адрес — из поля mTLS-запроса.")
                }

                ForEach(model.tokens) { entry in
                    TokenSection(entry: entry, isBusy: model.isBusy) {
                        Task { await model.testSign(slot: entry.info.slot) }
                    }
                }

                Section("Журнал") {
                    ForEach(model.log) { line in
                        VStack(alignment: .leading, spacing: 2) {
                            Text(line.text).foregroundStyle(color(for: line.level))
                            Text(line.date, style: .time).font(.caption2).foregroundStyle(.secondary)
                        }
                        .font(.footnote)
                    }
                }
            }
            .navigationTitle("Рутокен")
            .refreshable { await model.refresh() }
            .overlay { if model.isBusy { ProgressView().controlSize(.large) } }
            .sheet(item: $model.webTestURL) { url in
                WebTestView(url: url, trustedRootsPEM: model.standTrustRoots) { text in
                    model.appendFromWebView(text)
                }
                .onDisappear { model.reloadExtensionLog() }
            }
            .task { await model.start() }
        }
    }

    private func icon(for kind: ReaderKind) -> String {
        switch kind {
        case .nfc: "wave.3.right"
        case .usb: "cable.connector"
        case .vcr: "ipad.and.iphone"
        case .bluetoothOrUnknown: "antenna.radiowaves.left.and.right"
        }
    }

    private func color(for level: LogLine.Level) -> Color {
        switch level {
        case .info: .primary
        case .success: .green
        case .failure: .red
        }
    }
}

private struct TokenSection: View {
    let entry: TokenEntry
    let isBusy: Bool
    let onTestSign: () -> Void

    var body: some View {
        Section {
            LabeledContent("Модель", value: entry.info.model)
            LabeledContent("Серийный номер", value: entry.info.serialNumber)
            LabeledContent("Прошивка", value: entry.info.firmwareVersion)
            if let left = entry.info.userPinRetriesLeft, let max = entry.info.userPinMaxRetries {
                LabeledContent("Попыток PIN", value: "\(left) из \(max)")
            }
            LabeledContent("PSS (TLS 1.3)", value: entry.algorithms.contains(.rsaPssRsaeSha256) ? "да" : "нет")

            ForEach(entry.certificates) { cert in
                VStack(alignment: .leading, spacing: 4) {
                    Text(cert.commonName ?? cert.subject).font(.headline)
                    Text(cert.issuer).font(.caption).foregroundStyle(.secondary)
                    HStack {
                        Text("до \(cert.notValidAfter.formatted(date: .abbreviated, time: .omitted))")
                        Spacer()
                        if entry.usable.contains(cert) {
                            Text("годен").foregroundStyle(.green)
                        } else {
                            Text(cert.isValid() ? "не для mTLS" : "истёк").foregroundStyle(.red)
                        }
                    }
                    .font(.caption)
                }
            }

            Button("Тестовая подпись", systemImage: "signature", action: onTestSign)
                .disabled(isBusy || entry.usable.isEmpty)
        } header: {
            Text(entry.info.label)
        }
    }
}

private extension String {
    /// The stand (openssl s_server -www) wraps its report into <pre>; show it as plain text.
    var strippingHTML: String {
        replacingOccurrences(of: "<[^>]+>", with: "", options: .regularExpression)
            .replacingOccurrences(of: "&lt;", with: "<")
            .replacingOccurrences(of: "&gt;", with: ">")
            .replacingOccurrences(of: "&amp;", with: "&")
    }
}

extension URL: @retroactive Identifiable {
    public var id: String { absoluteString }
}
