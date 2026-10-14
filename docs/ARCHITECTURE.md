# iOS-браузер с аутентификацией по RSA-сертификату на Рутокен: архитектура и план

## 1. Задача и ограничения

Нужно открывать сайты, которые требуют **mutual TLS** с клиентским **RSA**-сертификатом. Закрытый ключ
хранится на Рутокен ЭЦП 3.0 (NFC / Bluetooth / USB-C) и не извлекается.

С RSA системный TLS Apple справится, но остаётся одна проблема: `WKWebView` принимает клиентский
сертификат только как `URLCredential(identity: SecIdentity)`. `SecIdentity` нельзя собрать из
ключа, доступного лишь через PKCS#11. Публичного API для «своего SecKey» на iOS нет, кроме
CryptoTokenKit-расширения. Значит, вариантов два:

| | A. Локальный прокси + SwiftNIO SSL (**рекомендуется**) | B. CryptoTokenKit persistent token extension |
|---|---|---|
| Как работает | WKWebView ходит через прокси внутри приложения. Прокси сам делает mTLS к сайту, подпись выполняется через `NIOSSLCustomPrivateKey`, то есть токеном через PKCS#11. | Сертификат и ключ токена регистрируются в системе как CTK-токен. WKWebView получает `SecIdentity` штатно, а подпись выполняет расширение. |
| NFC | Работает: подпись идёт в процессе приложения, NFC-UI доступен. | **Скорее не работает**: NFC-сессию может открыть только приложение на переднем плане, но не расширение. |
| PIN | Свой UI в приложении. | Через `TKTokenAuthOperation`. Как это поведёт себя на iOS, нужно проверять. |
| Bluetooth / USB | Работает. | Неизвестно, работает ли RtPcsc из процесса расширения. |
| Минимальная iOS | 17 (`WKWebsiteDataStore.proxyConfigurations`) | 14 |
| Сложность | Прокси с MITM к WKWebView только для доменов из allowlist. | Меньше кода в браузере, но много неизвестных в связке CTK + RtPcsc. |

**Решение:** основной путь — **A**. На вариант B делается короткий spike (этап 1), чтобы понять,
пригоден ли он как будущий режим без прокси для BT/USB-токенов.

## 2. Архитектура (вариант A)

```
┌───────────────────────────── iOS-приложение ──────────────────────────────┐
│ SwiftUI ── BrowserView (WKWebView)                                        │
│               │ dataStore.proxyConfigurations → CONNECT 127.0.0.1:<port>  │
│               ▼                                                           │
│ ┌──────────────────────── ProxyKit (SwiftNIO) ─────────────────────────┐  │
│ │ HTTP CONNECT handler (NIOHTTP1) + авторизация прокси                 │  │
│ │ RoutingPolicy: хост в allowlist?                                     │  │
│ │   нет → TCP-туннель (GlueHandler)                                    │  │
│ │   да  → MITM:                                                        │  │
│ │     входящий  NIOSSLServerHandler, лист-сертификат от эфемерного CA  │  │
│ │     исходящий NIOSSLClientHandler, клиентский сертификат с токена,   │  │
│ │               ключ = TokenPrivateKey: NIOSSLCustomPrivateKey         │  │
│ │     GlueHandler между ними: байты, без разбора HTTP                  │  │
│ └───────────────────────────────┬──────────────────────────────────────┘  │
│                                 │ sign(RSA, algorithm, bytes) → Future    │
│ TokenKit: actor TokenService ── rtpkcs11ecp ── RtPcsc                     │
│           PIN UI, выбор сертификата, NFC-сессии, мониторинг ридеров       │
└─────────────────────────────────┬─────────────────────────────────────────┘
                                  ▼
                 Рутокен ЭЦП 3.0 NFC / Bluetooth / USB-C
```

Почему SwiftNIO SSL, а не OpenSSL:
* `NIOSSLCustomPrivateKey` — штатная точка расширения под аппаратный ключ. Подпись асинхронная и
  возвращает `EventLoopFuture`, поэтому handshake спокойно ждёт, пока пользователь приложит карту
  и введёт PIN.
* BoringSSL уже вшит в пакет: не нужно собирать XCFramework, всё подключается через SPM.
* Обе стороны прокси (сервер для WKWebView и клиент к сайту) реализуются на одном стеке.

Зависимости (SPM): `swift-nio`, `swift-nio-ssl`, `swift-nio-transport-services` (по желанию),
`swift-certificates` + `swift-crypto` (локальный CA), `swift-log`.
Вендорные: `RtPcsc.xcframework` (≥ 4.0 для USB, 5.x актуальный), `rtpkcs11ecp.xcframework` из Рутокен SDK.

## 3. Модули

```
RutokenBrowser.xcodeproj
├─ App/                 точка входа, DI, Info.plist, entitlements
└─ Packages/
   ├─ BrowserFeature/   UI браузера, WKWebView, делегаты
   ├─ ProxyKit/         прокси, MITM-CA, маршрутизация, кеш сессий
   ├─ TokenKit/         RtPcsc + PKCS#11, TokenService, модели сертификатов
   └─ Core/             ошибки, логирование (без секретов), настройки
```

### 3.1 BrowserFeature
* `BrowserView` / `BrowserViewModel`: адресная строка, навигация, прогресс, вкладки (во второй итерации).
* `WebViewFactory`: общий `WKWebsiteDataStore` с `proxyConfigurations`; при включённом прокси
  отключается HTTP/3, чтобы QUIC не шёл в обход прокси.
* `NavigationDelegate.didReceive(challenge)`:
  * `ServerTrust`: если цепочка подписана эфемерным CA приложения, выполняется `useCredential`,
    иначе `performDefaultHandling`;
  * `ClientCertificate`: при работе через прокси не должен приходить (mTLS делает прокси), выполняется
    `performDefaultHandling`.
* Страницы ошибок: токен не найден, PIN заблокирован, сервер отклонил сертификат, NFC-таймаут.
* `WKDownload`, просмотр PDF, «Поделиться».

### 3.2 ProxyKit
* `LocalProxyServer`: слушает только на `127.0.0.1` с портом 0 (порт выбирает система). Требует
  `Proxy-Authorization` со случайным секретом, который передаётся в `ProxyConfiguration`.
* `RoutingPolicy`: allowlist доменов, редактируемый в настройках (по желанию — managed config через MDM).
* `MitmCertificateAuthority`: CA на P-256 генерируется в памяти при запуске. Лист-сертификаты
  выпускаются по SNI и кешируются. Ключи никуда не сохраняются.
* `UpstreamTLSFactory`: `TLSConfiguration.makeClientConfiguration()`:
  * `certificateChain` берётся из сертификата на токене (и промежуточных, если есть);
  * `privateKey = .privateKey(NIOSSLPrivateKey(customPrivateKey: TokenPrivateKey))`;
  * доверенные корни: системные + корни из настроек; проверка hostname;
  * ALPN: `http/1.1` (h2 во второй итерации, с прокидыванием результата во входящую сторону).
* **Кеш TLS-сессий и keep-alive**: при NFC токен нужен только для полного handshake.
* Выбор сертификата: из CertificateRequest берётся список `certificate_authorities`; если на токене
  несколько подходящих сертификатов, пользователю показывается выбор, и выбор запоминается для хоста.

### 3.3 TokenKit
* `ReaderMonitor`: `SCardGetStatusChange` по `\\?PnP?\Notification` с учётом поведения RtPcsc 5.0
  (число известных ридеров передаётся в старшем слове `dwCurrentState`). Тип ридера определяется
  через `SCARD_ATTR_VENDOR_IFD_TYPE`.
* `NFCSessionController`: `SCardConnect(SHARE_DIRECT)`, затем `START_NFC`, работа, `STOP_NFC` /
  `STOP_WITH_ERROR`; причина остановки берётся из `LAST_NFC_STOP_REASON`. Лимит — 20 с на сессию.
* `actor TokenService`: все PKCS#11-вызовы выполняются последовательно.
  * `listCertificates()` ищет `CKO_CERTIFICATE`, ключ связывается по `CKA_ID`;
  * `login(pin)` выполняет `C_Login(CKU_USER)` и разбирает `CKR_PIN_INCORRECT`/`LOCKED` вместе со счётчиком попыток;
  * `sign(keyID, algorithm, input)`, который используют сигнатурные алгоритмы TLS:
    * `rsa_pkcs1_sha256/384/512` (TLS 1.2) → `CKM_SHA256_RSA_PKCS` и т. п. либо `CKM_RSA_PKCS`
      над готовым DigestInfo;
    * `rsa_pss_rsae_sha256/384/512` (**обязательны для TLS 1.3**) → `CKM_SHA256_RSA_PKCS_PSS`
      либо `CKM_RSA_PKCS_PSS`. Если токен не поддерживает PSS, используется `CKM_RSA_X_509` с
      программным PSS-кодированием; если и это недоступно, upstream ограничивается TLS 1.2.
* `TokenPrivateKey: NIOSSLCustomPrivateKey`:
  * `signatureAlgorithms` — по механизмам, которые реально есть у токена (`C_GetMechanismList`);
  * `sign(channel:algorithm:data:)` отправляет задачу в `TokenService` и возвращает promise.
    При NFC одна сессия покрывает подключение, `C_Login` (если PIN не закеширован), `C_Sign` и `STOP_NFC`.
* `PinProvider`: протокол, реализация — SwiftUI-sheet. PIN хранится только в памяти и сбрасывается
  при уходе в фон или блокировке экрана. Сохранение в Keychain с биометрией — по желанию, во второй итерации.

## 4. Основной сценарий

1. Пользователь открывает `https://lk.example.ru`. WebKit отправляет `CONNECT lk.example.ru:443` в прокси.
2. Хост есть в allowlist, поэтому начинается upstream-handshake. Сервер присылает CertificateRequest.
3. Прокси запрашивает identity у `TokenService`:
   * если токена нет, показывается «Приложите карту / подключите токен»;
   * если сертификатов несколько, пользователь выбирает один;
   * затем вводится PIN.
4. BoringSSL вызывает `TokenPrivateKey.sign`, и подпись выполняется на токене. Handshake завершается,
   сессия кешируется.
5. Прокси поднимает TLS к WKWebView с лист-сертификатом. Делегат проверяет его по CA приложения,
   страница загружается.
6. Следующие запросы идут через keep-alive и резюмирование сессии, токен не требуется.

## 5. Требования к проекту
* iOS **17+**. Только реальное устройство для токена; симулятор подходит для тестов с программным ключом.
* Info.plist: `NFCReaderUsageDescription`, `com.apple.developer.nfc.readersession.iso7816.select-identifiers`
  (AID из документации Рутокен), `NSBluetoothAlwaysUsageDescription`.
* Entitlements: `com.apple.developer.nfc.readersession.formats = [TAG]`. Включить NFC capability в App ID.
* Export compliance: используется стандартная криптография (TLS) — как правило, освобождение.

## 6. План работ

| Этап | Содержание | Результат | Оценка |
|---|---|---|---|
| **0. Подготовка** | Список целевых сайтов, проверка TLS 1.2/1.3 и требований к клиентскому сертификату. Токены: ЭЦП 3.0 NFC и BT/USB-C. Рутокен SDK, разбор `rutoken-demoshift-ios`. Стенд: nginx с `ssl_verify_client on`, тестовый CA, RSA-2048 сертификаты на токенах. | Стенд, сертификаты | 3–5 дн |
| **1. Spike: токен** | Ридеры, NFC, `C_Login`, список сертификатов, `C_GetMechanismList`, подписи PKCS#1 v1.5 и PSS. **Ответ: поддерживает ли токен PSS.** | Подпись на iPhone | 1 нед |
| **1b. Spike: CTK (time-box 3 дн)** | Persistent token extension: работают ли RtPcsc, BT/USB и PIN из расширения. | Решение по варианту B | 3 дн |
| **2. Spike: NIO mTLS** | `NIOSSLClientHandler` + `TokenPrivateKey`, GET к стенду с iPhone по TLS 1.2 и 1.3. | mTLS с токеном | 1 нед |
| **3. Spike: прокси** | `proxyConfigurations`, CONNECT, туннель, MITM. **Проверить, что WebKit присылает ServerTrust-challenge для subresource, XHR и WebSocket.** | WKWebView грузит стенд | 1 нед |
| **Go/No-Go** | При провале этапа 3: fallback через `WKURLSchemeHandler` или вариант B для BT/USB. | Решение | — |
| **4. MVP** | Структура модулей, UI браузера, выбор сертификата, PIN, NFC-подсказки, allowlist, кеш сессий, страницы ошибок. | Работает на 1–2 целевых сайтах | 3 нед |
| **5. Надёжность и UX** | Пул соединений, h2, WebSocket, загрузки, повторы при NFC-таймауте, сброс при уходе в фон, автоподсказка добавить хост, если сервер запросил сертификат, локализация, VoiceOver. | Бета (TestFlight) | 2 нед |
| **6. Безопасность** | Прокси только на loopback и с авторизацией; CA только в памяти; PIN не логируется; проверка серверных цепочек; негативные тесты (подмена сертификата, чужой процесс на порту). | Отчёт и исправления | 1 нед |
| **7. Тесты и релиз** | Unit-тесты ProxyKit с NIO `EmbeddedChannel` и программным ключом вместо токена, CI на симуляторе. Ручная матрица: токен × iOS × сайт. App Store review notes (NFC, локальный прокси). | 1.0 | 1 нед |

**Итого:** около **9–11 недель** на одного iOS-разработчика. Первые 3–4 недели уходят на spike-и, которые
снимают риски.

### Результаты

* **Этап 1 (USB) пройден 2026-10-14.** iPhone, iOS 27, Rutoken ECP USB-A (FW 30.2) через
  переходник на USB-C. Ридер определяется как `Aktiv Rutoken Unknown USB 0`. Сертификаты читаются,
  вход по PIN работает (PIN может содержать буквы). Подпись `rsa_pss_rsae_sha256` RSA-2048 занимает
  **около 855 мс** и проверяется открытым ключом сертификата.
  NFC не проверен: для этого нужна платная команда разработчика.
* **Этап 2 пройден 2026-10-14.** iPhone выполнил HTTPS-запрос к стенду (`stand/run-stand.sh`, тогда ещё
  openssl s_server с `-Verify 2`) через SwiftNIO SSL. CertificateVerify подписан на токене через
  `TokenPrivateKey`. Сервер проверил цепочку `пользователь → промежуточный CA → корневой CA организации`.
  Что выяснилось по ходу:
  * Apple `SecTrust` (его использует NIOSSL с системными корнями) не принимает TLS-сертификаты сервера сроком
    больше 825 дней, даже от собственного CA. Это важно для будущего MITM-CA: листовые сертификаты выпускать
    на короткий срок.
  * Клиент отправлял только свой сертификат, без промежуточного; корпоративным серверам нужна полная
    цепочка — сделано позже (`App/ClientChain`).
* **Вариант B (CryptoTokenKit) отложен 2026-10-14.** Расширение и регистрация сделаны (`App/TokenExtension`),
  но на бесплатной команде (personal team) профиль разрешает только `keychain-access-groups = <TEAM_ID>.*`. Без группы
  `com.apple.token` приложение не видит удостоверения с токена (`-25300`), и расширение не вызывается.
  Нужна платная команда; будет ли тогда работать окно PIN и USB из расширения — не проверено.
* **Этап 3 пройден 2026-10-14.** Вкладка «Браузер»: WKWebView → `WKWebsiteDataStore.proxyConfigurations` →
  `LocalProxyServer` (127.0.0.1) → MITM для хостов из списка → mTLS с подписью токеном → стенд
  (`standserver`, keep-alive). Страница и все подресурсы (CSS, SVG, JS, `fetch`, XHR) загрузились,
  сервер видит сертификат пользователя с токена, TLS 1.3. ServerTrust-запросы WebKit приходят на новые соединения
  (3 проверки на 4 перехваченных соединения: WebKit кеширует решение по хосту).
  Замеры: PIN спрашивается один раз; WebKit открыл 3 соединения → 3 подписи на токене
  (~0,85 с каждая, выполняются по очереди: 846 / 843 / 1690 мс с ожиданием), страница целиком ~2,6 с после PIN.
  Одно предварительное соединение WebKit закрыл до рукопожатия (`EOF during handshake` на стенде), это не ошибка.
  Следующие шаги:
  * Сократить подписи: NIOSSL не умеет возобновлять TLS-сессии на клиенте. Варианты: пул upstream-соединений
    с разбором HTTP/1.1 в прокси или своя сборка с `SSL_SESSION` в BoringSSL.
  * Авторизация прокси (`Proxy-Authorization`) — сейчас прокси без пароля, слушает только 127.0.0.1.
  * Список хостов — из настроек/MDM.
* **Реальные корпоративные сайты, 2026-10-14: вход в корпоративный мессенджер через AD FS по токену прошёл.**
  Цепочка: мессенджер (туннель) → SAML → сервер AD FS → POST на `<adfs>:49443` (сертификат запрашивается
  при первом рукопожатии, TLS 1.2, подпись `rsa_pkcs1_sha256` на токене за 852 мс) → SAML-ответ →
  `<мессенджер>/_saml/validate` → токен входа. Что понадобилось:
  * **User-Agent как у Safari** (`applicationNameForUserAgent = "Version/<iOS> Mobile/15E148 Safari/604.1"`):
    веб-приложение выбирает JS-сборку по UA и без `Safari/` отдаёт legacy-сборку, которая падает, — кнопки
    входа нет.
  * **`NSAllowsArbitraryLoadsInWebContent`**: для доменных имён ATS отвергает сертификат прокси даже после
    принятия в `respondTo challenge` (для IP-адресов ATS не действует, поэтому на стенде этого не было).
    Настоящий сервер проверяет сам прокси.
  * **Промежуточный CA клиента** в цепочке (`App/ClientChain`): на токене только конечный сертификат.
  * **Корпоративный корень** для проверки серверов прокси (`App/TrustRoots`): внутренние сайты используют
    серверные сертификаты корпоративного CA, которому iOS не доверяет.
  * PIN запрашивается лениво, при первой подписи, поэтому можно перехватывать весь домен (`*.<домен>`):
    сайты, не запрашивающие сертификат, PIN не требуют.
  * WebView не открывает собственные схемы приложений (`<app>://`, попытка перейти в нативное приложение) —
    переход отменяется, сайт продолжает работать в вебе.
* **Корпоративная wiki по токену работает, 2026-10-14** (сервер сам запрашивает клиентский сертификат),
  в том числе в настольной версии (переключатель «Версия для компьютера»: `preferredContentMode = .desktop`
  + User-Agent Safari для Mac; без него сервер уводит iPhone в упрощённый мобильный интерфейс).
  Найдено по ходу: RtPcsc-обнаружение ридеров (`ReaderMonitor`) нужно запускать при старте приложения —
  без него PKCS#11 не видит USB-токен.

## 7. Риски
1. ~~**RSA-PSS на токене.**~~ **Снят 2026-10-14**: тестовый Rutoken ECP (FW 30.2, RtPKCS#11 2.21)
   аппаратно поддерживает `CKM_RSA_PKCS_PSS` и `CKM_SHA256/384/512_RSA_PKCS_PSS`, а также
   `CKM_RSA_PKCS` и `CKM_RSA_X_509` для ключей 512..4096 бит. TLS 1.3 возможен.
2. **WebKit + прокси.** Нужно проверить ServerTrust-challenge для всех типов запросов и обход прокси
   через QUIC. Проверяется на этапе 3.
3. **NFC.** Лимит 20 с на сессию и прикладывание карты на каждый полный handshake. Смягчается кешем
   сессий; для постоянной работы лучше BT или USB-C токен.
4. **Сайты, которые часто делают renegotiation** (запрос сертификата на отдельном пути в TLS 1.2).
   BoringSSL по умолчанию renegotiation запрещает. При необходимости включить
   `renegotiationSupport = .once` для конкретных хостов.

## 8. Ссылки
* Рутокен для iOS: https://dev.rutoken.ru/pages/viewpage.action?pageId=81527019
* https://github.com/AktivCo/rutoken-demoshift-ios (`PcscWrapper.swift`), https://github.com/AktivCo/rutoken-demobank-ios
* SwiftNIO SSL, `NIOSSLCustomPrivateKey`: https://github.com/apple/swift-nio-ssl
* `WKWebsiteDataStore.proxyConfigurations` (iOS 17+), CryptoTokenKit `TKTokenDriver` — Apple Developer Documentation
