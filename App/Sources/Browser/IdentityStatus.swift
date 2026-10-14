import Foundation

/// What happened when the proxy needed the token for a host; the browser turns these into
/// readable error pages instead of WebKit's generic "connection lost".
enum IdentityStatus: Sendable, Equatable {
    /// No token connected; the connection went on without a client certificate.
    case tokenMissing(host: String)
    /// The token has no valid certificate for client authentication.
    case noCertificate(host: String)
    /// The user cancelled the PIN prompt (or Face ID for the stored PIN).
    case pinCancelled(host: String)
    case loginFailed(host: String, reason: String)
    case signedIn
}
