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

/// Tracks PC/SC readers. USB tokens show up as PKCS#11 slots only while this discovery runs.
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
