#if canImport(RtPcscWrapper)
import Foundation
import RtPcscWrapper

public enum ReaderKind: Sendable {
    case nfc, usb, bluetoothOrUnknown, vcr
}

public struct Reader: Identifiable, Hashable, Sendable {
    public var id: String { name }
    public let name: String
    public let kind: ReaderKind
}

/// Tracks PC/SC readers and runs NFC exchanges. USB and Bluetooth tokens need no NFC session:
/// they show up as PKCS#11 slots by themselves.
public actor ReaderMonitor {
    private let wrapper = RtPcscWrapper()
    public private(set) var readers: [Reader] = []
    private var started = false
    private var subscribers: [UUID: AsyncStream<[Reader]>.Continuation] = [:]

    public init() {}

    /// Starts reader discovery once (the token isn't visible to PKCS#11 until RtPcsc runs)
    /// and returns a stream of reader lists: the current one first, then every change.
    public func start() async -> AsyncStream<[Reader]> {
        let (stream, continuation) = AsyncStream<[Reader]>.makeStream()
        let id = UUID()
        subscribers[id] = continuation
        continuation.onTermination = { _ in Task { await self.unsubscribe(id) } }
        if started {
            continuation.yield(readers)
            return stream
        }
        started = true
        guard let source = await wrapper.start() else { return stream }
        Task {
            for await list in source {
                let mapped = list.map { Reader(name: $0.name, kind: Self.kind($0.type)) }
                self.update(mapped)
            }
            self.finishAll()
        }
        return stream
    }

    public var nfcReader: Reader? { readers.first { $0.kind == .nfc } }

    /// Shows the system NFC sheet, waits for the card and runs `body` while it stays attached.
    /// The whole body must fit into the iOS NFC session limit (~20 s).
    public func withNfcExchange<T: Sendable>(
        waitMessage: String = "Приложите Рутокен к телефону",
        workMessage: String = "Идёт работа с Рутокен…",
        doneMessage: String = "Готово",
        _ body: @Sendable () async throws -> T
    ) async throws -> T {
        guard let reader = nfcReader else { throw Pkcs11Error.nfcFailed("NFC-ридер недоступен") }

        let statuses = await wrapper.startNfcExchange(onReader: reader.name, waitMessage: waitMessage, workMessage: workMessage)
        for await status in statuses {
            switch status {
            case .inProgress:
                do {
                    let result = try await body()
                    try? await wrapper.stopNfc(onReader: reader.name, withMessage: doneMessage)
                    return result
                } catch {
                    try? await wrapper.stopNfc(onReader: reader.name, withMessage: "Ошибка")
                    throw error
                }
            case .exchangeIsStopped(let error):
                throw Pkcs11Error.nfcFailed(String(describing: error))
            case .exchangeIsCompleted:
                break
            }
        }
        throw Pkcs11Error.nfcFailed("NFC-сессия завершилась")
    }

    private func update(_ readers: [Reader]) {
        self.readers = readers
        subscribers.values.forEach { $0.yield(readers) }
    }

    private func finishAll() {
        subscribers.values.forEach { $0.finish() }
        subscribers.removeAll()
    }

    private func unsubscribe(_ id: UUID) {
        subscribers[id] = nil
    }

    private static func kind(_ type: RtReaderType) -> ReaderKind {
        switch type {
        case .nfc: .nfc
        case .usb: .usb
        case .vcr: .vcr
        case .unknown: .bluetoothOrUnknown
        }
    }
}
#endif
