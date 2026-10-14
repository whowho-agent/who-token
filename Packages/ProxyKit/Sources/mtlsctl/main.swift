// mtlsctl: HTTPS GET with client authentication by a USB Rutoken key (macOS).
//   mtlsctl <https-url> [--ca extra-root.pem] [--tls12|--tls13]
import Darwin
import Foundation
import ProxyKit
import TokenKit

let arguments = Array(CommandLine.arguments.dropFirst())
let caPath = arguments.firstIndex(of: "--ca").flatMap { $0 + 1 < arguments.count ? arguments[$0 + 1] : nil }
let version: TLSVersionChoice = arguments.contains("--tls12") ? .tls12 : arguments.contains("--tls13") ? .tls13 : .automatic
guard let url = arguments.first(where: { $0.hasPrefix("https://") }).flatMap(URL.init(string:)) else {
    print("usage: mtlsctl <https-url> [--ca extra-root.pem] [--tls12|--tls13]")
    exit(2)
}

do {
    let service = try TokenService()
    guard let token = try await service.tokens().first else { print("Токен не найден"); exit(1) }
    guard let certificate = TokenCertificate.usableForClientAuth(try await service.certificates(slot: token.slot)).first else {
        print("На токене нет годных для mTLS сертификатов"); exit(1)
    }
    print("Сертификат: \(certificate.commonName ?? certificate.subject), до \(certificate.notValidAfter)")

    var buffer = [CChar](repeating: 0, count: 64)
    guard let raw = readpassphrase("PIN пользователя: ", &buffer, buffer.count, 0) else { exit(1) }
    let pin = String(cString: raw)
    buffer.withUnsafeMutableBufferPointer { $0.update(repeating: 0) }
    try await service.login(slot: token.slot, pin: pin)

    let key = TokenPrivateKey(
        service: service, slot: token.slot, keyID: certificate.keyID,
        supported: try await service.supportedAlgorithms(slot: token.slot)
    ) { algorithm, elapsed in
        print("Токен подписал CertificateVerify: \(algorithm.rawValue), \(elapsed.formatted(.units(allowed: [.milliseconds])))")
    }
    let roots = try caPath.map { [try Data(contentsOf: URL(fileURLWithPath: $0))] } ?? []
    let response = try await MTLSClient.get(url, certificate: certificate, privateKey: key, extraTrustRootsPEM: roots, version: version)
    print("\(response.tlsVersion), \(response.elapsed.formatted(.units(allowed: [.milliseconds]))): \(response.statusLine)")
    print(response.body)
    await service.logout(slot: token.slot)
} catch {
    print("Ошибка: \(error)")
    exit(1)
}
