# Рутокен Браузер

iOS-браузер для сайтов, требующих TLS-аутентификации клиента (mTLS) сертификатом, закрытый ключ
которого хранится на USB-токене Рутокен ЭЦП. Ключ не покидает токен: подпись выполняется на нём.

WebKit не умеет использовать ключи с токенов напрямую, поэтому приложение поднимает локальный прокси:
трафик к сайтам из списка расшифровывается внутри приложения и отправляется на сервер по TLS с
сертификатом с токена; остальные сайты идут туннелем без расшифровки. Подробности и результаты
проверок — в [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Требования

- macOS с Xcode 27 и [XcodeGen](https://github.com/yonaskolb/XcodeGen) (`brew install xcodegen`).
- iPhone или iPad с iOS 17+; USB-токен Рутокен ЭЦП (для USB-A нужен переходник на USB-C).
- Apple ID для подписи (бесплатная учётная запись подходит для установки на свои устройства).

## Сборка

```bash
cp Config/Local.xcconfig.example Config/Local.xcconfig
```

В `Config/Local.xcconfig` укажите свой Team ID (Xcode → Settings → Accounts) и уникальный bundle id,
например `com.example.RutokenBrowser.<TEAM_ID>`. Файл в git не попадает.

Сертификаты организации (в git не попадают, см. README в каждой папке):

- `App/ClientChain/*.pem` — промежуточные CA, выпустившие сертификат на токене (нужны серверам, которые
  проверяют полную цепочку, например AD FS);
- `App/TrustRoots/*.pem` — корневые CA организации, если серверные сертификаты внутренних сайтов
  выпущены ими.

```bash
xcodegen generate
open RutokenBrowser.xcodeproj
```

При первой сборке Xcode попросит доверить плагину SwiftLint из пакета RtPcsc — «Trust & Enable».
Из командной строки (с подключённым iPhone):

```bash
xcodebuild -project RutokenBrowser.xcodeproj -scheme RutokenBrowser -destination 'platform=iOS,name=<имя iPhone>' -derivedDataPath .build/DerivedData -skipPackagePluginValidation -allowProvisioningUpdates build
```

После установки с бесплатной учётной записью подтвердите разработчика на телефоне:
Настройки → Основные → VPN и управление устройством.

## Использование

1. Подключите токен к телефону и откройте приложение.
2. В настройках браузера добавьте сайты с входом по токену: хосты через запятую, можно `*.домен`.
3. Откройте сайт. PIN спрашивается, только когда сервер запросил сертификат.

Вкладка «Токен» — диагностика: ридеры, сертификаты, тестовая подпись, mTLS-запрос.

## Раздача команде

- **Без платной учётной записи Apple** сборку с вашей подписью другие устройства не установят:
  профиль бесплатной команды действует только для ваших устройств и 7 дней. Варианты: каждый собирает
  проект сам со своим Apple ID (шаги выше) либо переподписывает `.ipa` своим Apple ID (Sideloadly,
  AltStore), тоже на 7 дней.
- **С платной учётной записью** (Apple Developer Program): ad hoc (до 100 устройств по UDID) или
  TestFlight; для корпоративного распространения — MDM.

Перед распространением проверьте лицензионные условия Рутокен SDK на встраивание `rtpkcs11ecp` и `RtPcsc`.

## Тестовый стенд

HTTPS-сервер на Mac, пускающий только клиентов с сертификатом от заданных CA:

1. Положите CA сертификата с токена в `stand/ca/*.pem`.
2. `stand/run-stand.sh` — выведет адрес `https://<IP Mac>:8443/`.
3. В приложении добавьте IP Mac в сайты с входом по токену и откройте адрес.

Сервер логирует каждое TLS-рукопожатие — по нему видно, сколько подписей на токене стоила загрузка.

## Тесты и утилиты

```bash
cd Packages/TokenKit && swift test
cd Packages/ProxyKit && swift test
```

С токеном, вставленным в Mac:

```bash
cd Packages/TokenKit && swift run tokenctl list
```

```bash
cd Packages/ProxyKit && swift run mtlsctl https://<host>/ --ca <доп. корень.pem>
```

## Структура

| Путь | Что это |
|---|---|
| `Packages/TokenKit` | PKCS#11 (`rtpkcs11ecp`) и RtPcsc: сертификаты, вход по PIN, подпись RSA PKCS#1/PSS, ридеры; `tokenctl` |
| `Packages/ProxyKit` | локальный прокси для WKWebView, MITM-CA в памяти, mTLS через SwiftNIO SSL с ключом на токене; `mtlsctl`, `standserver` |
| `App/Sources/Browser` | браузер: WKWebView через прокси, PIN, настройки |
| `App/Sources/TokenLab` | вкладка диагностики токена |
| `App/TokenExtension`, `App/Sources/SystemToken` | эксперимент с CryptoTokenKit (отложен: нужна платная команда) |
| `stand/` | тестовый стенд |
| `docs/ARCHITECTURE.md` | архитектура, план, результаты |
