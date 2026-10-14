import Network
import Observation
import SwiftUI
import TokenKit
import UIKit

/// Finds the root CA of a site and hands it to iOS as a configuration profile. The user must compare
/// the fingerprint with the one from their IT department: the root comes over a connection that isn't
/// trusted yet, so on a hostile network it could be an attacker's.
@MainActor @Observable
final class RootCertificateModel {
    var address: String
    private(set) var root: RootCertificate?
    private(set) var error: String?
    private(set) var isLoading = false
    private(set) var profileOffered = false
    private let server = ProfileServer()

    init(address: String = "") {
        self.address = address
    }

    func find() async {
        isLoading = true
        defer { isLoading = false }
        root = nil
        error = nil
        profileOffered = false
        do {
            root = try await RootCertificateFinder.find(siteAddress: address)
            // Checked on the setup screen from now on.
            UserDefaults.standard.set(address.trimmingCharacters(in: .whitespaces), forKey: "workSite")
        } catch {
            self.error = "\(error)"
        }
    }

    /// iOS installs profiles only from Safari (or Mail/Files/AirDrop), so the app serves the profile
    /// on a local address and opens it in Safari, which offers to download it.
    func offerProfile() async {
        guard let root else { return }
        do {
            let url = try await server.serve(root.mobileConfig(), fileName: "root.mobileconfig")
            await UIApplication.shared.open(url)
            profileOffered = true
        } catch {
            self.error = "Не удалось подготовить профиль: \(error)"
        }
    }
}

struct RootCertificateView: View {
    @State var model: RootCertificateModel

    var body: some View {
        Form {
            Section {
                TextField("wiki.example.com", text: $model.address)
                    .keyboardType(.URL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .submitLabel(.search)
                    .onSubmit { Task { await model.find() } }
                Button("Найти корневой сертификат", systemImage: "magnifyingglass") { Task { await model.find() } }
                    .disabled(model.address.trimmingCharacters(in: .whitespaces).isEmpty || model.isLoading)
            } footer: {
                Text("Внутренний сайт, на котором Safari пишет, что соединение не является частным.")
            }

            if model.isLoading {
                Section { ProgressView("Проверяем сертификат сайта…") }
            }
            if let error = model.error {
                Section { Label(error, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.red) }
            }
            if let root = model.root {
                resultSections(root)
            }
        }
        .navigationTitle("Корневой сертификат")
        .navigationBarTitleDisplayMode(.inline)
        .task { if !model.address.isEmpty && model.root == nil { await model.find() } }
    }

    @ViewBuilder
    private func resultSections(_ root: RootCertificate) -> some View {
        Section("Найден корневой сертификат") {
            LabeledContent("Имя", value: root.name)
            LabeledContent("Действует до", value: root.notValidAfter.formatted(date: .long, time: .omitted))
            LabeledContent("Цепочка сайта", value: root.serverChain.joined(separator: " → "))
            if let url = root.downloadedFrom {
                LabeledContent("Скачан с", value: url.absoluteString)
            }
            if root.anchorsHost {
                Label("Подтверждает сертификат этого сайта", systemImage: "checkmark.seal.fill").foregroundStyle(.green)
            } else {
                Label("НЕ подтверждает сертификат этого сайта — не устанавливайте", systemImage: "xmark.octagon.fill")
                    .foregroundStyle(.red)
            }
        }
        Section {
            FingerprintView(fingerprint: root.sha256Fingerprint)
        } header: {
            Text("Отпечаток SHA-256")
        } footer: {
            Text("Сверьте все символы с отпечатком, который опубликовала ваша ИТ-служба. Совпадение «на глаз» по началу и концу не годится. Если отпечатка у вас нет — запросите его, прежде чем устанавливать: корень с полным доверием позволяет его владельцу подделывать любые сайты.")
        }
        if root.anchorsHost {
            Section {
                Button("Отпечаток совпадает, загрузить профиль", systemImage: "arrow.down.doc") {
                    Task { await model.offerProfile() }
                }
                if model.profileOffered {
                    Button("Профиль установлен — включить доверие", systemImage: "checkmark.shield") {
                        // No public link to Certificate Trust Settings; the prefs URL works on current iOS,
                        // otherwise Settings opens at the app.
                        let trust = URL(string: "App-prefs:General&path=About/CERT_TRUST_SETTINGS")!
                        UIApplication.shared.open(trust) { opened in
                            if !opened { UIApplication.shared.open(URL(string: UIApplication.openSettingsURLString)!) }
                        }
                    }
                }
            } footer: {
                if model.profileOffered {
                    Text("В Safari разрешите загрузку профиля, затем: Настройки → «Профиль загружен» → «Установить». После установки нажмите «включить доверие» (Настройки → Основные → Об этом устройстве → Доверие сертификатам) и включите переключатель у сертификата.")
                } else {
                    Text("Откроется Safari и предложит загрузить профиль конфигурации.")
                }
            }
        }
    }
}

/// The fingerprint in groups of four bytes, large and monospaced, for comparing character by character.
private struct FingerprintView: View {
    let fingerprint: String

    var body: some View {
        let bytes = fingerprint.split(separator: ":")
        let rows = stride(from: 0, to: bytes.count, by: 8).map { bytes[$0..<min($0 + 8, bytes.count)].joined(separator: " ") }
        VStack(alignment: .leading, spacing: 4) {
            ForEach(rows, id: \.self) { Text($0) }
        }
        .font(.system(.body, design: .monospaced))
        .textSelection(.enabled)
    }
}

/// Serves one file on 127.0.0.1 for a short while, so Safari can download it.
private final class ProfileServer: @unchecked Sendable {
    private var listener: NWListener?
    private var body = Data()
    private let queue = DispatchQueue(label: "ProfileServer")

    func serve(_ data: Data, fileName: String) async throws -> URL {
        listener?.cancel()
        body = data
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        let listener = try NWListener(using: parameters)
        listener.newConnectionHandler = { [weak self] connection in self?.respond(on: connection) }
        self.listener = listener
        let port: UInt16 = try await withCheckedThrowingContinuation { continuation in
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    listener.stateUpdateHandler = nil
                    continuation.resume(returning: listener.port?.rawValue ?? 0)
                case .failed(let error):
                    listener.stateUpdateHandler = nil
                    continuation.resume(throwing: error)
                default:
                    break
                }
            }
            listener.start(queue: queue)
        }
        // Safari requests the file right after the app goes to the background; keep it alive briefly.
        let task = await UIApplication.shared.beginBackgroundTask(withName: "ProfileServer")
        queue.asyncAfter(deadline: .now() + 60) { [weak self] in
            self?.listener?.cancel()
            Task { @MainActor in UIApplication.shared.endBackgroundTask(task) }
        }
        return URL(string: "http://127.0.0.1:\(port)/\(fileName)")!
    }

    private func respond(on connection: NWConnection) {
        connection.start(queue: queue)
        connection.receive(minimumIncompleteLength: 1, maximumLength: 16 * 1024) { [body] _, _, _, _ in
            var response = Data("""
            HTTP/1.1 200 OK\r
            Content-Type: application/x-apple-aspen-config\r
            Content-Length: \(body.count)\r
            Cache-Control: no-store\r
            Connection: close\r
            \r

            """.utf8)
            response.append(body)
            connection.send(content: response, completion: .contentProcessed { _ in connection.cancel() })
        }
    }
}
