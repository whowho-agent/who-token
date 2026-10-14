//===----------------------------------------------------------------------===//
//
// Local addition to swift-nio-ssl (see PATCH.md): client-side TLS session resumption.
//
// Licensed under Apache License v2.0, like the rest of this package.
//
//===----------------------------------------------------------------------===//

@_implementationOnly import CNIOBoringSSL

/// A TLS session established by a client connection that a later connection to the same server can offer
/// for resumption (TLS 1.2 session ID or ticket, TLS 1.3 PSK ticket). Resuming skips the certificate
/// exchange, so the client private key is not used again.
///
/// The underlying `SSL_SESSION` is immutable and reference counted, so the object can be shared freely.
public final class NIOSSLClientSession: @unchecked Sendable {
    fileprivate let ref: OpaquePointer

    /// Takes over one reference to `ref`.
    fileprivate init(owning ref: OpaquePointer) {
        self.ref = ref
    }

    deinit {
        CNIOBoringSSL_SSL_SESSION_free(self.ref)
    }

    /// Whether the session can still be offered (not expired, has a ticket or session ID).
    public var isResumable: Bool {
        CNIOBoringSSL_SSL_SESSION_is_resumable(self.ref) == 1
    }

    /// Seconds the session stays valid after it was issued, as granted by the server (ticket lifetime).
    public var timeout: UInt32 {
        CNIOBoringSSL_SSL_SESSION_get_timeout(self.ref)
    }
}

/// Called on the channel's event loop for every new resumable session the server issues: once per full
/// TLS 1.2 handshake, and for each TLS 1.3 NewSessionTicket (which arrives after the handshake).
public typealias NIOSSLClientSessionCallback = @Sendable (NIOSSLClientSession) -> Void

extension NIOSSLClientHandler {
    /// Like ``init(context:serverHostname:)``, but offers `session` for resumption and reports the
    /// sessions the server issues through `onNewSession`.
    ///
    /// BoringSSL only offers `session` if it is still valid and matches the context's protocol versions;
    /// otherwise, or if the server declines, a full handshake takes place.
    public convenience init(
        context: NIOSSLContext,
        serverHostname: String?,
        session: NIOSSLClientSession?,
        onNewSession: NIOSSLClientSessionCallback?
    ) throws {
        try self.init(context: context, serverHostname: serverHostname)
        if let session {
            // Takes its own reference; the handshake has not started yet.
            CNIOBoringSSL_SSL_set_session(self.connection.ssl, session.ref)
        }
        self.connection.newSessionCallback = onNewSession
    }
}

extension NIOSSLHandler {
    /// Whether the completed handshake resumed a previous session (no certificates were exchanged).
    ///
    /// This variable **is not thread-safe**: you **must** call it from the correct event loop thread.
    public var isSessionReused: Bool {
        CNIOBoringSSL_SSL_session_reused(self.connection.ssl) == 1
    }
}

extension NIOSSLContext {
    /// Clients never use BoringSSL's internal session cache, so enabling client caching only makes
    /// BoringSSL hand new sessions to the callback; server-side caching keeps its default.
    static func setClientSessionCallback(context: OpaquePointer) {
        CNIOBoringSSL_SSL_CTX_set_session_cache_mode(context, SSL_SESS_CACHE_BOTH)
        CNIOBoringSSL_SSL_CTX_sess_set_new_cb(context) { ssl, session in
            guard let ssl, let session, CNIOBoringSSL_SSL_is_server(ssl) == 0 else { return 0 }
            guard let callback = SSLConnection.loadConnectionFromSSL(ssl).newSessionCallback else { return 0 }
            // Returning 1 transfers BoringSSL's reference to the Swift object.
            callback(NIOSSLClientSession(owning: session))
            return 1
        }
    }
}
