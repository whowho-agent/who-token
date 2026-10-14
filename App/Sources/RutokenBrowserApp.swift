import SwiftUI
import TokenKit

@main
struct RutokenBrowserApp: App {
    @State private var prompter: PinPrompter
    @State private var browser: BrowserModel
    @State private var lab: TokenLabModel

    init() {
        let service = try? TokenService()
        let prompter = PinPrompter()
        let readerMonitor = ReaderMonitor()
        #if DEBUG
        // CryptoTokenKit extension diagnostics: its log lives in the shared keychain.
        AppLog.write("[extension log at launch]\n" + ExtensionLog.read().suffix(30).joined(separator: "\n"))
        #endif
        // USB tokens become visible to PKCS#11 only once RtPcsc reader discovery runs.
        Task {
            for await readers in await readerMonitor.start() {
                AppLog.write("[readers] \(readers.map(\.name))")
            }
        }
        _prompter = State(initialValue: prompter)
        _browser = State(initialValue: BrowserModel(service: service, prompter: prompter))
        _lab = State(initialValue: TokenLabModel(service: service, prompter: prompter, readerMonitor: readerMonitor))
    }

    var body: some Scene {
        WindowGroup {
            TabView {
                NavigationStack { BrowserView(model: browser) }
                    .tabItem { Label("Браузер", systemImage: "globe") }
                TokenLabView(model: lab)
                    .tabItem { Label("Токен", systemImage: "key.card") }
            }
            .sheet(item: $prompter.request) { request in
                PinEntrySheet(request: request) { prompter.submit($0) }
            }
        }
    }
}
