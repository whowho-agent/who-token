import CPkcs11
import Foundation

/// Single owner of the rtpkcs11ecp library. All PKCS#11 calls run on one serial queue,
/// so blocking token I/O never occupies Swift's cooperative thread pool.
public actor TokenService {
    private let queue = DispatchSerialQueue(label: "TokenKit.pkcs11")
    public nonisolated var unownedExecutor: UnownedSerialExecutor { queue.asUnownedSerialExecutor() }

    private var sessions: [UInt: CK_SESSION_HANDLE] = [:]

    public init() throws {
        var args = CK_C_INITIALIZE_ARGS()
        args.flags = CKF_OS_LOCKING_OK
        let rv = C_Initialize(&args)
        if rv != CKR_CRYPTOKI_ALREADY_INITIALIZED {
            try Pkcs11Error.check(rv, "C_Initialize")
        }
    }

    // MARK: - Tokens

    public func tokens() throws -> [TokenInfo] {
        try slotsWithToken().compactMap { try? tokenInfo(slot: $0) }
    }

    public func tokenInfo(slot: UInt) throws -> TokenInfo {
        var info = CK_TOKEN_INFO()
        try Pkcs11Error.check(C_GetTokenInfo(slot, &info), "C_GetTokenInfo")

        var extended = CK_TOKEN_INFO_EXTENDED()
        extended.ulSizeofThisStructure = CK_ULONG(MemoryLayout<CK_TOKEN_INFO_EXTENDED>.size)
        let hasExtended = C_EX_GetTokenInfoExtended(slot, &extended) == CKR_OK

        return TokenInfo(
            slot: slot,
            label: Self.string(info.label),
            model: Self.string(info.model),
            serialNumber: Self.string(info.serialNumber),
            firmwareVersion: "\(info.firmwareVersion.major).\(info.firmwareVersion.minor)",
            userPinRetriesLeft: hasExtended ? Int(extended.ulUserRetryCountLeft) : nil,
            userPinMaxRetries: hasExtended ? Int(extended.ulMaxUserRetryCount) : nil,
            isPinLocked: info.flags & CKF_USER_PIN_LOCKED != 0
        )
    }

    /// Signature algorithms the token can perform, in TLS preference order.
    public func supportedAlgorithms(slot: UInt) throws -> [SignatureAlgorithm] {
        var count: CK_ULONG = 0
        try Pkcs11Error.check(C_GetMechanismList(slot, nil, &count), "C_GetMechanismList")
        var mechanisms = [CK_MECHANISM_TYPE](repeating: 0, count: Int(count))
        try Pkcs11Error.check(C_GetMechanismList(slot, &mechanisms, &count), "C_GetMechanismList")
        let available = Set(mechanisms.prefix(Int(count)))
        return SignatureAlgorithm.allCases.filter { available.contains($0.mechanism) }
    }

    // MARK: - Certificates

    /// Certificates are public objects, so no login is required.
    public func certificates(slot: UInt) throws -> [TokenCertificate] {
        let session = try session(for: slot)
        var objectClass = CKO_CERTIFICATE
        let handles = try withUnsafeMutableBytes(of: &objectClass) { classBytes in
            var template = [CK_ATTRIBUTE(type: CKA_CLASS, pValue: classBytes.baseAddress, ulValueLen: CK_ULONG(classBytes.count))]
            return try findObjects(session: session, template: &template)
        }
        return handles.compactMap { handle in
            guard let der = try? attribute(CKA_VALUE, of: handle, session: session),
                  let keyID = try? attribute(CKA_ID, of: handle, session: session) else { return nil }
            let label = (try? attribute(CKA_LABEL, of: handle, session: session)).flatMap { String(data: $0, encoding: .utf8) } ?? ""
            return try? TokenCertificate(keyID: keyID, label: label, der: der)
        }
    }

    // MARK: - Login and signing

    public func login(slot: UInt, pin: String) throws {
        let session = try session(for: slot)
        var pinBytes = Array(pin.utf8)
        defer { pinBytes.withUnsafeMutableBufferPointer { $0.update(repeating: 0) } }
        let rv = C_Login(session, CKU_USER, &pinBytes, CK_ULONG(pinBytes.count))
        switch rv {
        case CKR_OK, CKR_USER_ALREADY_LOGGED_IN:
            return
        case CKR_PIN_INCORRECT:
            throw Pkcs11Error.pinIncorrect(retriesLeft: (try? tokenInfo(slot: slot))?.userPinRetriesLeft)
        default:
            try Pkcs11Error.check(rv, "C_Login")
        }
    }

    public func isLoggedIn(slot: UInt) -> Bool {
        guard let session = sessions[slot] else { return false }
        var info = CK_SESSION_INFO()
        guard C_GetSessionInfo(session, &info) == CKR_OK else { return false }
        return info.state == CKS_RO_USER_FUNCTIONS || info.state == CKS_RW_USER_FUNCTIONS
    }

    public func logout(slot: UInt) {
        guard let session = sessions[slot] else { return }
        C_Logout(session)
    }

    /// Signs `message` with the private key whose `CKA_ID` is `keyID`. Requires a prior `login`.
    public func sign(_ message: Data, keyID: Data, algorithm: SignatureAlgorithm, slot: UInt) throws -> Data {
        try sign(message, keyID: keyID, mechanism: algorithm.mechanism, pssParams: algorithm.pssParams, slot: slot)
    }

    /// Signs a precomputed digest (CryptoTokenKit / Security.framework style). Requires a prior `login`.
    public func signDigest(_ digest: Data, keyID: Data, algorithm: DigestSignatureAlgorithm, slot: UInt) throws -> Data {
        try sign(algorithm.tokenInput(for: digest), keyID: keyID, mechanism: algorithm.mechanism, pssParams: algorithm.pssParams, slot: slot)
    }

    /// Slot holding the token with this serial number (as shown in `TokenInfo.serialNumber`).
    public func slot(serialNumber: String) throws -> UInt? {
        try slotsWithToken().first { (try? tokenInfo(slot: $0))?.serialNumber == serialNumber }
    }

    private func sign(_ input: Data, keyID: Data, mechanism type: CK_MECHANISM_TYPE, pssParams: CK_RSA_PKCS_PSS_PARAMS?, slot: UInt) throws -> Data {
        let session = try session(for: slot)
        // Private keys are invisible before login, so report that rather than "key not found".
        guard isLoggedIn(slot: slot) else { throw Pkcs11Error.notLoggedIn }
        let key = try privateKey(keyID: keyID, session: session)

        var mechanism = CK_MECHANISM(mechanism: type, pParameter: nil, ulParameterLen: 0)
        var params = pssParams ?? CK_RSA_PKCS_PSS_PARAMS()
        let rv = withUnsafeMutableBytes(of: &params) { paramBytes in
            if pssParams != nil {
                mechanism.pParameter = paramBytes.baseAddress
                mechanism.ulParameterLen = CK_ULONG(paramBytes.count)
            }
            return C_SignInit(session, &mechanism, key)
        }
        if rv == CKR_USER_NOT_LOGGED_IN { throw Pkcs11Error.notLoggedIn }
        try Pkcs11Error.check(rv, "C_SignInit")

        var bytes = [UInt8](input)
        var length: CK_ULONG = 0
        try Pkcs11Error.check(C_Sign(session, &bytes, CK_ULONG(bytes.count), nil, &length), "C_Sign")
        var signature = [UInt8](repeating: 0, count: Int(length))
        try Pkcs11Error.check(C_Sign(session, &bytes, CK_ULONG(bytes.count), &signature, &length), "C_Sign")
        return Data(signature.prefix(Int(length)))
    }

    // MARK: - Slot events

    /// Emits whenever a token is inserted or removed (USB/BT plug, NFC card tap).
    public nonisolated func slotEvents() -> AsyncStream<UInt> {
        AsyncStream { continuation in
            let thread = Thread {
                while true {
                    var slot: CK_SLOT_ID = 0
                    let rv = C_WaitForSlotEvent(0, &slot, nil)
                    if rv == CKR_CRYPTOKI_NOT_INITIALIZED { break }
                    if rv == CKR_OK { continuation.yield(slot) }
                }
                continuation.finish()
            }
            thread.name = "TokenKit.slotEvents"
            thread.start()
        }
    }

    /// Waits until a token is present in any slot, e.g. right after an NFC card was tapped.
    public func waitForToken(timeout: Duration = .seconds(5)) async throws -> UInt {
        let clock = ContinuousClock()
        let deadline = clock.now + timeout
        while clock.now < deadline {
            if let slot = try slotsWithToken().first { return slot }
            try await Task.sleep(for: .milliseconds(100))
        }
        throw Pkcs11Error.tokenNotPresent
    }

    // MARK: - Private

    private func slotsWithToken() throws -> [UInt] {
        var count: CK_ULONG = 0
        try Pkcs11Error.check(C_GetSlotList(CK_BBOOL(CK_TRUE), nil, &count), "C_GetSlotList")
        var slots = [CK_SLOT_ID](repeating: 0, count: Int(count))
        try Pkcs11Error.check(C_GetSlotList(CK_BBOOL(CK_TRUE), &slots, &count), "C_GetSlotList")
        let present = Array(slots.prefix(Int(count)))
        // Drop sessions of tokens that were removed; their handles are no longer valid.
        for slot in sessions.keys where !present.contains(slot) {
            sessions[slot] = nil
        }
        return present
    }

    private func session(for slot: UInt) throws -> CK_SESSION_HANDLE {
        if let session = sessions[slot] {
            var info = CK_SESSION_INFO()
            if C_GetSessionInfo(session, &info) == CKR_OK { return session }
            sessions[slot] = nil
        }
        var session: CK_SESSION_HANDLE = 0
        try Pkcs11Error.check(C_OpenSession(slot, CKF_SERIAL_SESSION, nil, nil, &session), "C_OpenSession")
        sessions[slot] = session
        return session
    }

    private func privateKey(keyID: Data, session: CK_SESSION_HANDLE) throws -> CK_OBJECT_HANDLE {
        var objectClass = CKO_PRIVATE_KEY
        var id = [UInt8](keyID)
        let handles = try withUnsafeMutableBytes(of: &objectClass) { classBytes in
            try id.withUnsafeMutableBytes { idBytes in
                var template = [
                    CK_ATTRIBUTE(type: CKA_CLASS, pValue: classBytes.baseAddress, ulValueLen: CK_ULONG(classBytes.count)),
                    CK_ATTRIBUTE(type: CKA_ID, pValue: idBytes.baseAddress, ulValueLen: CK_ULONG(idBytes.count))
                ]
                return try findObjects(session: session, template: &template)
            }
        }
        guard let key = handles.first else { throw Pkcs11Error.keyNotFound }
        return key
    }

    private func findObjects(session: CK_SESSION_HANDLE, template: inout [CK_ATTRIBUTE]) throws -> [CK_OBJECT_HANDLE] {
        try Pkcs11Error.check(C_FindObjectsInit(session, &template, CK_ULONG(template.count)), "C_FindObjectsInit")
        defer { C_FindObjectsFinal(session) }
        var result: [CK_OBJECT_HANDLE] = []
        var batch = [CK_OBJECT_HANDLE](repeating: 0, count: 32)
        while true {
            var found: CK_ULONG = 0
            try Pkcs11Error.check(C_FindObjects(session, &batch, CK_ULONG(batch.count), &found), "C_FindObjects")
            guard found > 0 else { return result }
            result += batch.prefix(Int(found))
        }
    }

    private func attribute(_ type: CK_ATTRIBUTE_TYPE, of object: CK_OBJECT_HANDLE, session: CK_SESSION_HANDLE) throws -> Data {
        var query = CK_ATTRIBUTE(type: type, pValue: nil, ulValueLen: 0)
        try Pkcs11Error.check(C_GetAttributeValue(session, object, &query, 1), "C_GetAttributeValue")
        var buffer = [UInt8](repeating: 0, count: Int(query.ulValueLen))
        try buffer.withUnsafeMutableBytes { bytes in
            query.pValue = bytes.baseAddress
            try Pkcs11Error.check(C_GetAttributeValue(session, object, &query, 1), "C_GetAttributeValue")
        }
        return Data(buffer.prefix(Int(query.ulValueLen)))
    }

    private static func string<T>(_ tuple: T) -> String {
        withUnsafeBytes(of: tuple) { bytes in
            String(decoding: bytes, as: UTF8.self).trimmingCharacters(in: .whitespaces.union(.controlCharacters))
        }
    }
}
