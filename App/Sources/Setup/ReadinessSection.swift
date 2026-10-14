import SwiftUI

/// Summary header: app icon and how many setup steps are left.
struct SetupHeader: View {
    let remaining: Int

    var body: some View {
        HStack(spacing: 14) {
            Image("Logo")
                .resizable()
                .frame(width: 56, height: 56)
                .clipShape(.rect(cornerRadius: 13, style: .continuous))
            VStack(alignment: .leading, spacing: 3) {
                Text("Рутокен для Safari").font(.headline)
                if remaining == 0 {
                    Label("Всё готово", systemImage: "checkmark.circle.fill")
                        .font(.subheadline)
                        .foregroundStyle(.green)
                } else {
                    Text(remaining == 1 ? "Остался 1 шаг" : "Осталось шагов: \(remaining)")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .padding(.vertical, 4)
    }
}

/// What Safari needs to sign in with the token: each step with its state and a way to fix it.
struct ReadinessSection: View {
    @Bindable var model: SetupModel
    let openRootCertificate: () -> Void

    var body: some View {
        Section {
            StepRow(state: model.token != nil ? .ok : .missing, title: "Токен",
                    detail: model.token != nil ? "Подключён" : "Вставьте USB-токен")
            StepRow(state: model.isRegistered ? .ok : .missing, title: "Сертификат в Safari",
                    detail: model.isRegistered ? "Доступен" : "Не подключён", action: registerAction)
            StepRow(state: Self.state(model.safariExtensionEnabled), title: "Расширение Safari",
                    detail: extensionDetail, action: extensionAction)
            StepRow(state: Self.siteAccessState(model), title: "Доступ к сайтам",
                    detail: siteAccessDetail, action: siteAccessAction)
            StepRow(state: model.pinExpiry != nil ? .ok : .missing, title: "PIN",
                    detail: model.pinExpiry.map { "До \($0.formatted(date: .omitted, time: .shortened))" } ?? "Не введён")
            Button(action: openRootCertificate) {
                StepRow(state: Self.rootState(model), title: "Сертификат сервера", detail: rootDetail, showsChevron: true)
            }
            .buttonStyle(.plain)
        } header: {
            Text("Настройка")
        }
    }

    /// Steps not done yet, for the header.
    static func remaining(_ model: SetupModel) -> Int {
        let states: [StepRow.State] = [
            model.token != nil ? .ok : .missing,
            model.isRegistered ? .ok : .missing,
            state(model.safariExtensionEnabled),
            siteAccessState(model),
            model.pinExpiry != nil ? .ok : .missing,
            rootState(model)
        ]
        return states.filter { $0 != .ok && $0 != .optional }.count
    }

    // MARK: States

    private var extensionDetail: String {
        switch model.safariExtensionEnabled {
        case true?: "Включено"
        case false?: "Выключено"
        case nil: "Не удалось проверить"
        }
    }

    private var extensionAction: StepAction? {
        guard model.safariExtensionEnabled != true else { return nil }
        let model = model
        return StepAction(title: "Открыть") { model.openSafariExtensionSettings() }
    }

    private var registerAction: StepAction? {
        guard !model.isRegistered, model.token != nil else { return nil }
        let model = model
        return StepAction(title: "Подключить") { Task { await model.register() } }
    }

    private static func siteAccessState(_ model: SetupModel) -> StepRow.State {
        guard let report = model.extensionReport else { return .unknown }
        switch report.allSitesAllowed {
        case true?: return .ok
        case false?: return .missing
        case nil: return report.sawHTTPSPage ? .ok : .unknown
        }
    }

    private var siteAccessDetail: String {
        switch Self.siteAccessState(model) {
        case .ok: "Разрешён"
        case .missing: "Запрещён"
        default: "Откройте любой сайт в Safari"
        }
    }

    private var siteAccessAction: StepAction? {
        guard Self.siteAccessState(model) == .missing else { return nil }
        let model = model
        return StepAction(title: "Открыть") { model.openSafariExtensionSettings() }
    }

    private static func rootState(_ model: SetupModel) -> StepRow.State {
        if model.isCheckingWorkSite { return .checking }
        // Not configured: optional, needed only if a site shows a certificate warning.
        if model.workSite.trimmingCharacters(in: .whitespaces).isEmpty { return .optional }
        return state(model.workSiteTrusted)
    }

    private var rootDetail: String {
        let site = model.workSite.trimmingCharacters(in: .whitespaces)
        guard !site.isEmpty else { return "Если сайт пишет, что соединение не частное" }
        switch model.workSiteTrusted {
        case true?: return "\(site) — доверен"
        case false?: return "\(site) — не доверен"
        case nil: return model.isCheckingWorkSite ? site : "\(site) — нет связи"
        }
    }

    private static func state(_ value: Bool?) -> StepRow.State {
        switch value {
        case true?: .ok
        case false?: .missing
        case nil: .unknown
        }
    }
}

struct StepAction {
    let title: String
    let perform: () -> Void
}

struct StepRow: View {
    enum State { case ok, missing, unknown, checking, optional }

    let state: State
    let title: String
    let detail: String
    var action: StepAction?
    var showsChevron = false

    var body: some View {
        HStack(spacing: 12) {
            icon.frame(width: 22)
            VStack(alignment: .leading, spacing: 1) {
                Text(title)
                Text(detail).font(.footnote).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 8)
            if let action {
                Button(action.title, action: action.perform)
                    .buttonStyle(.bordered)
                    .buttonBorderShape(.capsule)
                    .controlSize(.small)
            }
            if showsChevron {
                Image(systemName: "chevron.forward")
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(.tertiary)
            }
        }
        .contentShape(.rect)
    }

    @ViewBuilder
    private var icon: some View {
        switch state {
        case .ok: Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
        case .missing: Image(systemName: "exclamationmark.circle.fill").foregroundStyle(.orange)
        case .unknown: Image(systemName: "questionmark.circle.fill").foregroundStyle(.secondary)
        case .checking: ProgressView().controlSize(.small)
        case .optional: Image(systemName: "circle.dashed").foregroundStyle(.tertiary)
        }
    }
}
