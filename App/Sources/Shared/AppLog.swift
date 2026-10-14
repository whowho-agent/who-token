import Foundation

/// Spike diagnostics: Documents/lab.log, readable from the Mac with
/// `xcrun devicectl device copy from --domain-type appDataContainer ...`.
enum AppLog {
    private static let file = URL.documentsDirectory.appending(path: "lab.log")
    private static let queue = DispatchQueue(label: "AppLog")

    static func write(_ line: String) {
        let stamp = Date().formatted(.dateTime.hour().minute().second())
        let data = Data("\(stamp) \(line)\n".utf8)
        queue.async {
            if let handle = try? FileHandle(forWritingTo: file) {
                handle.seekToEndOfFile()
                handle.write(data)
                try? handle.close()
            } else {
                try? data.write(to: file)
            }
        }
    }
}
