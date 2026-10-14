# swift-nio-ssl: local copy with client TLS session resumption

Base: swift-nio-ssl **2.37.5** (`322f3c2a4a21df31c84ca416bf65ee5e9059e440`, BoringSSL `817ab07e`),
the latest release as of 2026-10-14. Upstream has no client-side session resumption API: no access to
`SSL_SESSION`, `SSL_set_session` or `SSL_CTX_sess_set_new_cb`, and BoringSSL's client cache mode is off,
so every client connection does a full handshake. ProxyKit needs resumption so that the token is not asked
to sign a CertificateVerify for every upstream connection.

## What is kept

Only what the `NIOSSL` product needs: `Sources/CNIOBoringSSL` (15 MB, unmodified), `Sources/CNIOBoringSSLShims`,
`Sources/NIOSSL` (without `Docs.docc`), license files. `Package.swift` is trimmed accordingly (no tests,
benchmarks, sample executables or swift-certificates dependency) and suppresses warnings in this third-party
code, as SwiftPM does for remote packages. The package keeps the identity `swift-nio-ssl` and product `NIOSSL`,
so dependants refer to it exactly as to the upstream package.

## The patch (`client-session-resumption.patch`, additive)

* New `Sources/NIOSSL/ClientSessionResumption.swift`:
  * `NIOSSLClientSession` — reference-counted wrapper of `SSL_SESSION` (`isResumable`, `timeout`).
  * `NIOSSLClientHandler(context:serverHostname:session:onNewSession:)` — `SSL_set_session` before the
    handshake and a per-connection callback for sessions the server issues.
  * `NIOSSLHandler.isSessionReused` (`SSL_session_reused`).
  * `NIOSSLContext.setClientSessionCallback` — `SSL_CTX_set_session_cache_mode(SSL_SESS_CACHE_BOTH)` and an
    `SSL_CTX_sess_set_new_cb` trampoline to the connection's callback. BoringSSL clients never use the internal
    cache, so this only makes BoringSSL report new client sessions; server-side caching keeps its default.
* `SSLContext.swift`: one call to `setClientSessionCallback` in the designated initializer.
* `SSLConnection.swift`: `ssl` private → internal; new stored `newSessionCallback`.
* `NIOSSLHandler.swift`: `connection` private → internal.

Changed lines are marked `// PATCH`.

## Upgrading

1. Check whether the new upstream release has its own client session API; if so, drop this copy and
   go back to the remote package in `Packages/ProxyKit/Package.swift`.
2. Otherwise copy `Sources/CNIOBoringSSL`, `Sources/CNIOBoringSSLShims`, `Sources/NIOSSL` (minus `Docs.docc`)
   and the license files from the new release over this directory, update the revision in `Package.swift`
   (and its target settings if upstream changed them), then `patch -p1 < client-session-resumption.patch`.
3. `cd Packages/ProxyKit && swift test` — `SessionResumptionTests` check that resumption works.
