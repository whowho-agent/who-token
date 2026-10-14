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

        if message["action"] as? String == "findRoot" {
            let site = message["site"] as? String ?? ""
            // The request completes asynchronously; the context is only used once, from this task.
            nonisolated(unsafe) let context = context
            Task {
                let reply: [String: Any]
                do {
                    let root = try await RootCertificateFinder.find(siteAddress: site)
                    reply = [
                        "name": root.name,
                        "fingerprint": root.sha256Fingerprint,
                        "notAfter": root.notValidAfter.timeIntervalSince1970,
                        "anchors": root.anchorsHost,
                        "chain": root.serverChain,
                        "downloadedFrom": root.downloadedFrom?.absoluteString ?? "",
                        "profile": root.mobileConfig().base64EncodedString()
                    ]
                } catch {
                    reply = ["error": "\(error)"]
                }
                let response = NSExtensionItem()
                response.userInfo = [SFExtensionMessageKey: reply]
                context.completeRequest(returningItems: [response], completionHandler: nil)
            }
            return
        }

        switch message["action"] as? String {
        case "setPin":
            if let pin = message["pin"] as? String, !pin.isEmpty {
                SharedPin.store(pin)
                SharedPin.clearFailure()
                ExtensionLog.append("safari: PIN entered in Safari popup")
            }
        case "heartbeat":
            SafariExtensionReport.store(allSitesAllowed: message["allSites"] as? Bool ?? false)
        case "log":
            #if DEBUG
            ExtensionLog.append("safari js: \(message["text"] as? String ?? "")")
            #endif
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
        var status: [String: Any] = ["pinShared": expiry != nil, "expires": expiry?.timeIntervalSince1970 ?? 0]
        if let failure = SharedPin.lastFailure {
            status["failure"] = failure.text
            status["failureAge"] = Date.now.timeIntervalSince(failure.date)
        }
        return status
    }
}
