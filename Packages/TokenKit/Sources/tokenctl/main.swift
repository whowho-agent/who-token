// tokenctl: checks TokenKit against a real USB Rutoken on macOS.
//   tokenctl list                       tokens, certificates, signature algorithms (no PIN needed)
//   tokenctl root <site>                root CA of a site as a .mobileconfig (compare the SHA-256!)
//   tokenctl sign [algorithm]           PIN prompt, signs a test message with each usable certificate
//                                       and verifies it with the certificate's public key
import CryptoKit
import Darwin
import Foundation
import Security
import TokenKit

let arguments = CommandLine.arguments.dropFirst()
let command = arguments.first ?? "list"
let formatter = ISO8601DateFormatter()
formatter.formatOptions = [.withFullDate]

if command == "root", let site = arguments.dropFirst().first {
    // tokenctl root <site>: find the root CA anchoring the site and write <name>.mobileconfig
    do {
        let root = try await RootCertificateFinder.find(siteAddress: site)
        print("Цепочка сервера: \(root.serverChain.joined(separator: " → "))")
        print("Корень: \(root.name), до \(formatter.string(from: root.notValidAfter))")
        if let url = root.downloadedFrom { print("Скачан: \(url.absoluteString)") }
        print("SHA-256: \(root.sha256Fingerprint)")
        print("Подтверждает сайт: \(root.anchorsHost ? "да" : "НЕТ")")
        let file = "\(root.name).mobileconfig"
        try root.mobileConfig().write(to: URL(fileURLWithPath: file))
        print("Профиль: \(file)")
    } catch {
        print("Ошибка: \(error)")
        exit(1)
    }
    exit(0)
}

do {
    let service = try TokenService()
    let tokens = try await service.tokens()
    if tokens.isEmpty { print("Токены не найдены") }

    for token in tokens {
        print("Слот \(token.slot): \(token.label) — \(token.model), s/n \(token.serialNumber), FW \(token.firmwareVersion)")
        if let left = token.userPinRetriesLeft, let max = token.userPinMaxRetries {
            print("  PIN: осталось попыток \(left)/\(max)\(token.isPinLocked ? ", ЗАБЛОКИРОВАН" : "")")
        }
        let algorithms = try await service.supportedAlgorithms(slot: token.slot)
        print("  Алгоритмы TLS: \(algorithms.map(\.rawValue).joined(separator: ", "))")

        let certificates = try await service.certificates(slot: token.slot)
        let usable = Set(TokenCertificate.usableForClientAuth(certificates))
        for cert in certificates {
            let status = usable.contains(cert) ? "годен для mTLS" : (cert.isValid() ? "не clientAuth" : "истёк/не начал действовать")
            print("  • \(cert.commonName ?? cert.subject) [\(cert.label)]")
            print("    \(formatter.string(from: cert.notValidBefore)) – \(formatter.string(from: cert.notValidAfter)), \(status)")
        }

        guard command == "sign" else { continue }
        let algorithm = arguments.dropFirst().first.flatMap(SignatureAlgorithm.init(rawValue:)) ?? .rsaPssRsaeSha256
        guard algorithms.contains(algorithm) else { print("  \(algorithm.rawValue) не поддерживается"); continue }
        guard !usable.isEmpty else { print("  Нет годных сертификатов"); continue }

        var buffer = [CChar](repeating: 0, count: 64)
        guard let raw = readpassphrase("  PIN пользователя: ", &buffer, buffer.count, 0) else { continue }
        let pin = String(cString: raw)
        buffer.withUnsafeMutableBufferPointer { $0.update(repeating: 0) }
        try await service.login(slot: token.slot, pin: pin)

        let message = Data("tokenctl self-test \(Date())".utf8)
        for cert in usable.sorted(by: { $0.notValidBefore > $1.notValidBefore }) {
            let start = ContinuousClock.now
            let signature = try await service.sign(message, keyID: cert.keyID, algorithm: algorithm, slot: token.slot)
            let elapsed = ContinuousClock.now - start
            let ok = cert.verify(signature: signature, of: message, algorithm: algorithm)
            print("  \(algorithm.rawValue) [\(cert.label)]: \(signature.count * 8) бит, \(elapsed.formatted(.units(allowed: [.milliseconds]))), проверка: \(ok ? "OK" : "ОШИБКА")")
        }
        // Digest signing, as a CryptoTokenKit extension receives it from the system TLS stack.
        let digestAlgorithms: [SecKeyAlgorithm] = [.rsaSignatureDigestPSSSHA256, .rsaSignatureDigestPKCS1v15SHA256]
        for cert in usable {
            for secAlgorithm in digestAlgorithms {
                let digest = Data(SHA256.hash(data: message))
                let algorithm = DigestSignatureAlgorithm(secAlgorithm)!
                let signature = try await service.signDigest(digest, keyID: cert.keyID, algorithm: algorithm, slot: token.slot)
                let ok = cert.verify(signature: signature, of: digest, secKeyAlgorithm: secAlgorithm)
                print("  \(secAlgorithm.rawValue) [\(cert.label)]: проверка: \(ok ? "OK" : "ОШИБКА")")
            }
        }
        await service.logout(slot: token.slot)
    }
} catch {
    print("Ошибка: \(error)")
    exit(1)
}
