import SwiftUI
import TokenKit

@main
struct RutokenApp: App {
    @State private var setup: SetupModel

    init() {
        let readerMonitor = ReaderMonitor()
        #if DEBUG
        // Extension diagnostics: their log lives in the shared keychain.
        AppLog.write("[keychain] shared group: \(SharedKeychain.accessGroup ?? "none"), token driver: \(SystemTokenRegistry.extensionID)")
        AppLog.write("[extension log at launch]\n" + ExtensionLog.read().suffix(300).joined(separator: "\n"))
        #endif
        _setup = State(initialValue: SetupModel(service: try? TokenService(), readerMonitor: readerMonitor))
    }

    var body: some Scene {
        WindowGroup {
            SetupView(model: setup)
        }
    }
}
