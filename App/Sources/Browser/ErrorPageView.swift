import SwiftUI

/// Native page shown over the web view when a navigation fails.
struct ErrorPageView: View {
    let error: BrowserError
    let host: String
    let retry: () -> Void
    let openSettings: () -> Void

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                Image(systemName: error.systemImage)
                    .font(.system(size: 48))
                    .foregroundStyle(.orange)
                    .padding(.top, 40)
                VStack(spacing: 6) {
                    Text(error.title)
                        .font(.title2.bold())
                    if !host.isEmpty {
                        Text(host)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                }
                .multilineTextAlignment(.center)
                Text(error.message)
                    .multilineTextAlignment(.center)
                if let hint = error.hint {
                    Label(hint, systemImage: "lightbulb")
                        .font(.callout)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(12)
                        .background(.fill.tertiary, in: .rect(cornerRadius: 10))
                }
                Button("Повторить", systemImage: "arrow.clockwise", action: retry)
                    .buttonStyle(.borderedProminent)
                    .controlSize(.large)
                if error.suggestsSettings {
                    Button("Открыть настройки", systemImage: "gearshape", action: openSettings)
                }
                if let details = error.details {
                    DisclosureGroup("Подробности") {
                        Text(details)
                            .font(.footnote.monospaced())
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.top, 4)
                    }
                    .font(.callout)
                }
            }
            .padding(24)
            .frame(maxWidth: 520)
            .frame(maxWidth: .infinity)
        }
        .background(Color(.systemBackground))
    }
}

/// First-launch hint when nothing has been opened yet.
struct BrowserEmptyState: View {
    let openSettings: () -> Void

    var body: some View {
        ContentUnavailableView {
            Label("Введите адрес сайта", systemImage: "globe")
        } description: {
            Text("Наберите адрес в строке вверху, например portal.example.ru, и нажмите «Перейти».\n\nЧтобы входить на сайты по сертификату с Рутокена, добавьте их в настройках в «Сайты с входом по токену».")
        } actions: {
            Button("Открыть настройки", systemImage: "gearshape", action: openSettings)
        }
        .background(Color(.systemBackground))
    }
}
