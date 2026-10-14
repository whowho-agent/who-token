import Crypto
import Foundation
import NIOConcurrencyHelpers
import NIOCore
import NIOSSL
import NIOTLS

/// Upstream TLS sessions per server and client certificate. A resumed handshake has no CertificateVerify,
/// so the token is not asked to sign again (~0.85 s per signature, and the token signs one at a time).
///
/// Cached sessions keep authenticating as the user without the token: clear the cache when the user signs
/// out of the token. Sessions are kept in memory only.
public final class UpstreamSessionCache: Sendable {
    public struct Key: Hashable, Sendable {
        public let host: String
        public let port: Int
        /// SHA-256 of the client certificate, nil for connections without one: a session never changes
        /// whether or as whom the client authenticated.
        public let certificate: Data?

        public init(host: String, port: Int, identity: ClientIdentity?) {
            self.host = host
            self.port = port
            certificate = identity.map { Data(SHA256.hash(data: $0.certificate.der)) }
        }
    }

    /// What one connection got from `checkout`.
    struct Lease: Sendable {
        let cache: UpstreamSessionCache
        let key: Key
        let session: NIOSSLClientSession?
        /// Sessions issued on connections started before `removeAll` are not stored.
        let generation: UInt64
        /// Set for the connection doing the first full handshake to `key`, which others wait for.
        let leaderID: UInt64?

        func store(_ session: NIOSSLClientSession) { cache.store(session, from: self) }
        func finish() { cache.finish(self) }
    }

    private struct Entry {
        let session: NIOSSLClientSession
        let stored: ContinuousClock.Instant
    }

    private struct InFlight {
        let leaderID: UInt64
        var waiters: [UInt64: CheckedContinuation<NIOSSLClientSession?, Never>] = [:]
    }

    private struct State {
        var entries: [Key: Entry] = [:]
        var inFlight: [Key: InFlight] = [:]
        var generation: UInt64 = 0
        var nextID: UInt64 = 0

        mutating func makeID() -> UInt64 {
            nextID += 1
            return nextID
        }

        mutating func usableSession(for key: Key, maximumAge: Duration) -> NIOSSLClientSession? {
            guard let entry = entries[key] else { return nil }
            if ContinuousClock.now - entry.stored < maximumAge, entry.session.isResumable { return entry.session }
            entries[key] = nil
            return nil
        }
    }

    private let state = NIOLockedValueBox(State())
    private let maximumAge: Duration
    private let maximumEntries: Int
    private let firstHandshakeWait: Duration

    /// - Parameters:
    ///   - maximumAge: Upper bound on session reuse on top of the server's own ticket lifetime, so the
    ///     token is asked again from time to time even if nobody signs out.
    ///   - firstHandshakeWait: How long a connection waits for a full handshake to the same server
    ///     that is already running (WebKit opens several connections at once) instead of signing itself.
    ///     The wait ends early when that handshake yields a session or turns out not to.
    public init(
        maximumAge: Duration = .seconds(3600),
        maximumEntries: Int = 256,
        firstHandshakeWait: Duration = .seconds(30)
    ) {
        self.maximumAge = maximumAge
        self.maximumEntries = maximumEntries
        self.firstHandshakeWait = firstHandshakeWait
    }

    /// Forgets all sessions; connections already in progress don't add theirs either.
    public func removeAll() {
        let waiters = state.withLockedValue { state in
            state.entries.removeAll()
            state.generation += 1
            defer { state.inFlight.removeAll() }
            return state.inFlight.values.flatMap(\.waiters.values)
        }
        waiters.forEach { $0.resume(returning: nil) }
    }

    public var count: Int {
        state.withLockedValue { $0.entries.count }
    }

    /// Returns a session to resume, or makes the caller the leader for `key`, or waits for the current leader.
    func checkout(_ key: Key) async -> Lease {
        enum Decision { case resume(NIOSSLClientSession), lead(UInt64), wait }
        let (decision, generation) = state.withLockedValue { state -> (Decision, UInt64) in
            if let session = state.usableSession(for: key, maximumAge: maximumAge) {
                return (.resume(session), state.generation)
            }
            if state.inFlight[key] != nil { return (.wait, state.generation) }
            let id = state.makeID()
            state.inFlight[key] = InFlight(leaderID: id)
            return (.lead(id), state.generation)
        }
        switch decision {
        case .resume(let session):
            return Lease(cache: self, key: key, session: session, generation: generation, leaderID: nil)
        case .lead(let id):
            return Lease(cache: self, key: key, session: nil, generation: generation, leaderID: id)
        case .wait:
            let session = await waitForLeader(key)
            // Without a session (leader failed or the server doesn't resume) do a full handshake right away.
            return Lease(cache: self, key: key, session: session, generation: generation, leaderID: nil)
        }
    }

    private func waitForLeader(_ key: Key) async -> NIOSSLClientSession? {
        let maximumAge = maximumAge
        let wait = firstHandshakeWait
        return await withCheckedContinuation { continuation in
            enum Outcome { case done(NIOSSLClientSession?), waiting(UInt64) }
            let outcome = state.withLockedValue { state -> Outcome in
                if let session = state.usableSession(for: key, maximumAge: maximumAge) { return .done(session) }
                guard state.inFlight[key] != nil else { return .done(nil) }
                let id = state.makeID()
                state.inFlight[key]!.waiters[id] = continuation
                return .waiting(id)
            }
            switch outcome {
            case .done(let session):
                continuation.resume(returning: session)
            case .waiting(let id):
                // The leader takes too long (slow server, PIN dialog left open): sign without it.
                Task { [weak self] in
                    try? await Task.sleep(for: wait)
                    let waiter = self?.state.withLockedValue { $0.inFlight[key]?.waiters.removeValue(forKey: id) }
                    waiter?.resume(returning: nil)
                }
            }
        }
    }

    private func store(_ session: NIOSSLClientSession, from lease: Lease) {
        guard session.isResumable else { return }
        let waiters = state.withLockedValue { state -> [CheckedContinuation<NIOSSLClientSession?, Never>] in
            guard lease.generation == state.generation else { return [] }
            state.entries[lease.key] = Entry(session: session, stored: .now)
            if state.entries.count > maximumEntries,
               let oldest = state.entries.min(by: { $0.value.stored < $1.value.stored })?.key {
                state.entries[oldest] = nil
            }
            defer { state.inFlight[lease.key] = nil }
            return state.inFlight[lease.key].map { Array($0.waiters.values) } ?? []
        }
        waiters.forEach { $0.resume(returning: session) }
    }

    /// The connection can no longer produce a session; release whoever waits for it. Idempotent.
    private func finish(_ lease: Lease) {
        guard let leaderID = lease.leaderID else { return }
        let waiters = state.withLockedValue { state -> [CheckedContinuation<NIOSSLClientSession?, Never>] in
            guard state.inFlight[lease.key]?.leaderID == leaderID else { return [] }
            defer { state.inFlight[lease.key] = nil }
            return Array(state.inFlight[lease.key]!.waiters.values)
        }
        waiters.forEach { $0.resume(returning: nil) }
    }
}

/// Sits behind `NIOSSLClientHandler` and tells the cache when the leading connection is done:
/// TLS 1.2 issues the session within the handshake, TLS 1.3 tickets follow it shortly after.
final class SessionLeaseHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer

    /// A TLS 1.3 server sends its tickets right after receiving the client Finished, i.e. within one round trip.
    static let ticketGrace: TimeAmount = .seconds(2)

    private let lease: UpstreamSessionCache.Lease

    init(lease: UpstreamSessionCache.Lease) {
        self.lease = lease
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if case TLSUserEvent.handshakeCompleted = event, lease.leaderID != nil {
            let tls = try? context.pipeline.syncOperations.handler(type: NIOSSLClientHandler.self)
            if tls?.tlsVersion == .tlsv13 {
                let lease = lease
                context.eventLoop.scheduleTask(in: Self.ticketGrace) { lease.finish() }
            } else {
                lease.finish()
            }
        }
        context.fireUserInboundEventTriggered(event)
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        lease.finish()
    }
}

extension UpstreamTLS {
    /// Adds the TLS client handler to an upstream pipeline, resuming the lease's session if it has one.
    static func addClientHandlers(
        to pipeline: ChannelPipeline.SynchronousOperations,
        context: NIOSSLContext,
        serverHostname: String?,
        lease: UpstreamSessionCache.Lease?
    ) throws {
        guard let lease else {
            try pipeline.addHandler(NIOSSLClientHandler(context: context, serverHostname: serverHostname))
            return
        }
        try pipeline.addHandler(NIOSSLClientHandler(
            context: context, serverHostname: serverHostname,
            session: lease.session, onNewSession: { lease.store($0) }
        ))
        try pipeline.addHandler(SessionLeaseHandler(lease: lease))
    }
}
