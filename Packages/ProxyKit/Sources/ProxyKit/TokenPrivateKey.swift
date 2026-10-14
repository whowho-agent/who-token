import Foundation
import NIOCore
import NIOSSL
import TokenKit

/// Private key that lives on a Rutoken: BoringSSL asks it to sign the TLS CertificateVerify,
/// the signature is produced by the token through `TokenService`. Requires a prior `login`.
public final class TokenPrivateKey: NIOSSLCustomPrivateKey, Hashable, @unchecked Sendable {
    public typealias Signer = @Sendable (Data, TokenKit.SignatureAlgorithm) async throws -> Data

    public let slot: UInt
    public let keyID: Data
    public let signatureAlgorithms: [NIOSSL.SignatureAlgorithm]
    private let signer: Signer
    private let onSign: (@Sendable (TokenKit.SignatureAlgorithm, Duration) -> Void)?

    public convenience init(
        service: TokenService,
        slot: UInt,
        keyID: Data,
        supported: [TokenKit.SignatureAlgorithm],
        onSign: (@Sendable (TokenKit.SignatureAlgorithm, Duration) -> Void)? = nil
    ) {
        self.init(slot: slot, keyID: keyID, supported: supported, onSign: onSign) { message, algorithm in
            try await service.sign(message, keyID: keyID, algorithm: algorithm, slot: slot)
        }
    }

    /// `signer` performs the actual signature; tests substitute a software key for the token.
    public init(
        slot: UInt,
        keyID: Data,
        supported: [TokenKit.SignatureAlgorithm],
        onSign: (@Sendable (TokenKit.SignatureAlgorithm, Duration) -> Void)? = nil,
        signer: @escaping Signer
    ) {
        self.signer = signer
        self.slot = slot
        self.keyID = keyID
        self.onSign = onSign
        // PSS first: mandatory for TLS 1.3, preferred for TLS 1.2.
        let order: [TokenKit.SignatureAlgorithm] = [
            .rsaPssRsaeSha256, .rsaPssRsaeSha384, .rsaPssRsaeSha512,
            .rsaPkcs1Sha256, .rsaPkcs1Sha384, .rsaPkcs1Sha512
        ]
        signatureAlgorithms = order.filter(supported.contains).map(\.nioAlgorithm)
    }


    public func sign(channel: Channel, algorithm: NIOSSL.SignatureAlgorithm, data: ByteBuffer) -> EventLoopFuture<ByteBuffer> {
        let promise = channel.eventLoop.makePromise(of: ByteBuffer.self)
        guard let tokenAlgorithm = TokenKit.SignatureAlgorithm(nio: algorithm) else {
            promise.fail(Pkcs11Error.mechanismNotSupported)
            return promise.futureResult
        }
        let message = Data(data.readableBytesView)
        promise.completeWithTask { [signer, onSign] in
            let start = ContinuousClock.now
            let signature = try await signer(message, tokenAlgorithm)
            onSign?(tokenAlgorithm, ContinuousClock.now - start)
            return ByteBuffer(bytes: signature)
        }
        return promise.futureResult
    }

    /// TLS client authentication never decrypts with the client key.
    public func decrypt(channel: Channel, data: ByteBuffer) -> EventLoopFuture<ByteBuffer> {
        channel.eventLoop.makeFailedFuture(Pkcs11Error.mechanismNotSupported)
    }

    public static func == (lhs: TokenPrivateKey, rhs: TokenPrivateKey) -> Bool {
        lhs.slot == rhs.slot && lhs.keyID == rhs.keyID
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(slot)
        hasher.combine(keyID)
    }
}

extension TokenKit.SignatureAlgorithm {
    var nioAlgorithm: NIOSSL.SignatureAlgorithm {
        switch self {
        case .rsaPkcs1Sha256: .rsaPkcs1Sha256
        case .rsaPkcs1Sha384: .rsaPkcs1Sha384
        case .rsaPkcs1Sha512: .rsaPkcs1Sha512
        case .rsaPssRsaeSha256: .rsaPssRsaeSha256
        case .rsaPssRsaeSha384: .rsaPssRsaeSha384
        case .rsaPssRsaeSha512: .rsaPssRsaeSha512
        }
    }

    init?(nio: NIOSSL.SignatureAlgorithm) {
        guard let match = Self.allCases.first(where: { $0.nioAlgorithm == nio }) else { return nil }
        self = match
    }
}
