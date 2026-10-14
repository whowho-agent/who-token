import Foundation
import SafariServices
import TokenKit

/// Native side of the Safari extension: receives the PIN from the popup and hands it to the
/// CryptoTokenKit token extension through the shared keychain (that extension has no UI and iOS
/// shows no PIN prompt for it).
final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
    func beginRequest(with context: NSExtensionContext) {
        let request = context.inputItems.first as? NSExtensionItem
        let message = request?.userInfo?[SFExtensionMessageKey] as? [String: Any] ?? [:]

        switch message["action"] as? String {
        case "setPin":
            if let pin = message["pin"] as? String, !pin.isEmpty {
                SharedPin.store(pin)
                ExtensionLog.append("safari: PIN entered in Safari popup")
            }
        case "clearPin":
            SharedPin.clear()
            ExtensionLog.append("safari: PIN cleared from Safari popup")
        default:
            break
        }

        let response = NSExtensionItem()
        response.userInfo = [SFExtensionMessageKey: status()]
        context.completeRequest(returningItems: [response], completionHandler: nil)
    }

    private func status() -> [String: Any] {
        let expiry = SharedPin.load() != nil ? SharedPin.expiry : nil
        return ["pinShared": expiry != nil, "expires": expiry?.timeIntervalSince1970 ?? 0]
    }
}
