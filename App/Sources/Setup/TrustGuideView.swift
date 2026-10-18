import SwiftUI
import UIKit

/// How to install the root certificate profile and turn on full trust for it. iOS has no link an app
/// may use to open Certificate Trust Settings (the private prefs URLs are refused), so the path is
/// spelled out step by step.
struct TrustGuideView: View {
    let site: String
    let rootName: String?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            List {
                Section {
                    VStack(spacing: 10) {
                        Image(systemName: "checkmark.shield.fill")
                            .font(.system(size: 44))
                            .foregroundStyle(.tint)
                        Text("Включите доверие сертификату")
                            .font(.title3.weight(.semibold))
                        Text(site.isEmpty
                             ? "Установленный профиль сам по себе доверия не даёт."
                             : "\(site) пока не доверен: установленный профиль сам по себе доверия не даёт.")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: .infinity)
                    .listRowBackground(Color.clear)
                }
                Section("Если профиль ещё не установлен") {
                    step(1, "Откройте приложение **Настройки**")
                    step(2, "Вверху нажмите **Профиль загружен**")
                    step(3, "Нажмите **Установить** и введите код-пароль iPhone")
                }
                Section("Затем включите доверие") {
                    step(1, "**Настройки** → **Основные** → **Об этом устройстве**")
                    step(2, "Прокрутите в самый низ: **Доверие сертификатам**")
                    step(3, "Включите переключатель у **\(rootName ?? "корневого сертификата")** и нажмите **Продолжить**")
                }
                Section {
                    Button("Открыть Настройки", systemImage: "gear") {
                        UIApplication.shared.open(URL(string: UIApplication.openSettingsURLString)!)
                    }
                } footer: {
                    Text("Откроются настройки «Рутокен»: вернитесь кнопкой «‹» вверху слева до главной страницы Настроек. Когда вернётесь в приложение, оно проверит сайт само.")
                }
            }
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("Готово") { dismiss() } }
            }
        }
    }

    private func step(_ number: Int, _ text: LocalizedStringKey) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text("\(number)")
                .font(.footnote.weight(.bold))
                .foregroundStyle(.white)
                .frame(width: 22, height: 22)
                .background(.tint, in: .circle)
            Text(text)
        }
    }
}
