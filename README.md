# Рутокен для Safari

Вход в обычном Safari на iPhone и iPad на сайты, требующие TLS-аутентификации клиента (mTLS)
сертификатом, закрытый ключ которого хранится на USB-токене Рутокен ЭЦП. Ключ не покидает токен:
подпись выполняется на нём.

Как это устроено:

- **Драйвер токена** (`App/TokenExtension`, расширение CryptoTokenKit). Приложение регистрирует в системе
  сертификаты с токена; когда сайт запрашивает сертификат, Safari сам вызывает драйвер, и тот подписывает
  на токене через PKCS#11 (`rtpkcs11ecp`) и RtPcsc.
- **Расширение Safari «Рутокен»** (`App/SafariExtension`). iOS не спрашивает PIN для токена сама, поэтому
  PIN вводится кнопкой «Рутокен» в Safari (или в приложении) и передаётся драйверу через общий keychain
  на 24 часа.
- **Приложение «Рутокен»** — экран настройки: статус токена, подключение к Safari, PIN, инструкция.

Подробности, история проверок и отказ от варианта со встроенным браузером — в
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Встроенный браузер с прокси сохранён в теге `browser-proxy`.

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

```bash
xcodegen generate
open Rutoken.xcodeproj
```

При первой сборке Xcode попросит доверить плагину SwiftLint из пакета RtPcsc — «Trust & Enable».
Из командной строки (с подключённым iPhone):

```bash
xcodebuild -project Rutoken.xcodeproj -scheme Rutoken -destination 'platform=iOS,name=<имя iPhone>' -derivedDataPath .build/DerivedData -skipPackagePluginValidation -allowProvisioningUpdates build
```

После установки с бесплатной учётной записью подтвердите разработчика на телефоне:
Настройки → Основные → VPN и управление устройством.

## Настройка на устройстве

1. Подключите токен, откройте «Рутокен» и нажмите «Подключить токен к Safari».
2. Настройки → Приложения → Safari → Расширения → «Рутокен»: включите и разрешите на нужных сайтах.
3. Если сайты организации используют собственный корневой сертификат, установите его профилем и
   включите полное доверие: кнопка «Установить корневой сертификат сайта…» в приложении или «Сертификат
   этого сайта…» в расширении (сверьте отпечаток!), подробно — в
   [docs/INSTALL.md](docs/INSTALL.md#корпоративный-корневой-сертификат) (профиль из файла сертификата
   делает `tools/make-root-profile.sh`).
4. Введите PIN кнопкой «Рутокен» в Safari (значок «аА» в адресной строке) или в приложении.
   Если Safari пишет, что не может установить безопасное соединение, — введите PIN и обновите страницу.

PIN хранится на устройстве 24 часа и защищён только код-паролем устройства: расширения не могут
показать Face ID. Неверный PIN удаляется сразу, чтобы не тратить попытки токена.

## Раздача команде

Пошаговая инструкция для коллег (сборка из исходников, Sideloadly, первая настройка):
[docs/INSTALL.md](docs/INSTALL.md).

- **Без платной учётной записи Apple** сборку с вашей подписью другие устройства не установят:
  профиль бесплатной команды действует только для ваших устройств и 7 дней. Варианты: каждый собирает
  проект сам со своим Apple ID (шаги выше) либо переподписывает `.ipa` своим Apple ID (Sideloadly,
  AltStore), тоже на 7 дней.
- **С платной учётной записью** (Apple Developer Program): ad hoc (до 100 устройств по UDID) или
  TestFlight; для корпоративного распространения — MDM (заодно раздаёт корневой сертификат).

Перед распространением проверьте лицензионные условия Рутокен SDK на встраивание `rtpkcs11ecp` и `RtPcsc`.

## Тестовый стенд

HTTPS-сервер на Mac (`openssl s_server`), пускающий только клиентов с сертификатом от заданных CA:

1. Положите CA сертификата с токена в `stand/ca/*.pem`.
2. `stand/run-stand.sh` — выведет адрес `https://<IP Mac>:8443/`.
3. Установите `stand/pki/stand-ca.pem` на iPhone профилем с полным доверием и откройте адрес в Safari.

## Тесты и утилиты

```bash
cd Packages/TokenKit && swift test
```

С токеном, вставленным в Mac:

```bash
cd Packages/TokenKit && swift run tokenctl list
```

## Структура

| Путь | Что это |
|---|---|
| `Packages/TokenKit` | PKCS#11 (`rtpkcs11ecp`) и RtPcsc: сертификаты, вход по PIN, подпись RSA PKCS#1/PSS (сообщение и хеш), ридеры, общий keychain; `tokenctl` |
| `App/Sources` | приложение: экран настройки, регистрация токена в системе |
| `App/TokenExtension` | драйвер токена CryptoTokenKit |
| `App/SafariExtension` | расширение Safari: ввод PIN |
| `stand/` | тестовый стенд |
| `tools/make-root-profile.sh` | профиль `.mobileconfig` для установки корневого сертификата на iPhone |
| `tools/build-neutral-ipa.sh` | нейтральная `dist/Rutoken-unsigned.ipa` (без подписи и личных данных) для Sideloadly |
| `docs/ARCHITECTURE.md` | архитектура, план, результаты |
