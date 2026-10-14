import SwiftUI

/// Everything Safari needs to sign in with the token, each with its state and a button that goes
/// straight to where it is fixed.
struct ReadinessSection: View {
    @Bindable var model: SetupModel
    let openRootCertificate: (String) -> Void

    var body: some View {
        Section {
            CheckRow(state: tokenState, title: "Токен подключён", detail: tokenDetail)
            CheckRow(state: registeredState, title: "Сертификат доступен в Safari", detail: registeredDetail, action: registerAction)
            CheckRow(state: extensionState, title: "Расширение «Рутокен» включено", detail: extensionDetail, action: extensionAction)
            CheckRow(state: siteAccessState, title: "Доступ расширения к сайтам", detail: siteAccessDetail, action: siteAccessAction)
            CheckRow(state: pinState, title: "PIN введён", detail: pinDetail)
            workSiteRow
        } header: {
            Text("Готовность")
        } footer: {
            Text("Статус обновляется, когда вы возвращаетесь в приложение.")
        }
    }

    // MARK: Rows

    private var tokenState: CheckRow.State { model.token != nil ? .ok : .missing }
    private var tokenDetail: String? { model.token == nil ? "Вставьте USB-токен (USB-A — через переходник)" : nil }

    private var registeredState: CheckRow.State { model.isRegistered ? .ok : .missing }
    private var registeredDetail: String? { model.isRegistered ? nil : "Нужен подключённый токен с действующим сертификатом" }
    private var registerAction: CheckAction? {
        guard !model.isRegistered, model.token != nil else { return nil }
        let model = model
        return CheckAction(title: "Подключить") { Task { await model.register() } }
    }

    private var extensionState: CheckRow.State { state(model.safariExtensionEnabled) }
    private var extensionDetail: String? {
        model.safariExtensionEnabled == nil ? "Не удалось проверить: откройте настройки и убедитесь" : nil
    }
    private var extensionAction: CheckAction? {
        guard model.safariExtensionEnabled != true else { return nil }
        let model = model
        return CheckAction(title: "Открыть") { model.openSafariExtensionSettings() }
    }

    private var siteAccessAction: CheckAction? {
        guard siteAccessState != .ok else { return nil }
        let model = model
        return CheckAction(title: "Открыть") { model.openSafariExtensionSettings() }
    }

    private var pinState: CheckRow.State { model.pinExpiry != nil ? .ok : .missing }
    private var pinDetail: String {
        if let expiry = model.pinExpiry { return "до \(expiry.formatted(date: .omitted, time: .shortened))" }
        return "Введите ниже или кнопкой «Рутокен» в Safari"
    }

    @ViewBuilder
    private var workSiteRow: some View {
        VStack(alignment: .leading, spacing: 8) {
            CheckRow(
                state: model.isCheckingWorkSite ? .checking : state(model.workSiteTrusted),
                title: "Сертификат рабочего сайта доверен",
                detail: workSiteDetail,
                action: workSiteAction
            )
            HStack {
                TextField("Рабочий сайт, например wiki.example.com", text: $model.workSite)
                    .keyboardType(.URL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .submitLabel(.done)
                    .onSubmit { Task { await model.checkWorkSite() } }
                    .font(.subheadline)
                Button("Проверить") { Task { await model.checkWorkSite() } }
                    .font(.subheadline)
                    .disabled(model.workSite.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
    }

    private var siteAccessState: CheckRow.State {
        guard let report = model.extensionReport else { return .unknown }
        return report.allSitesAllowed ? .ok : .missing
    }

    private var siteAccessDetail: String? {
        guard let report = model.extensionReport else {
            return "Неизвестно: откройте любой сайт в Safari, расширение сообщит о себе"
        }
        if report.allSitesAllowed { return nil }
        return "«Другие веб-сайты» → «Разрешить», иначе «Рутокен» не подскажет, когда нужен PIN"
    }

    private var workSiteDetail: String? {
        guard !model.workSite.trimmingCharacters(in: .whitespaces).isEmpty else {
            return "Укажите адрес внутреннего сайта, чтобы проверить корневой сертификат организации"
        }
        switch model.workSiteTrusted {
        case true?: return nil
        case false?: return "Установите корневой сертификат и включите доверие к нему"
        case nil: return model.isCheckingWorkSite ? nil : "Сайт недоступен — проверьте адрес и сеть"
        }
    }

    private var workSiteAction: CheckAction? {
        guard model.workSiteTrusted == false else { return nil }
        let site = model.workSite
        let open = openRootCertificate
        return CheckAction(title: "Исправить") { open(site) }
    }

    private func state(_ value: Bool?) -> CheckRow.State {
        switch value {
        case true?: .ok
        case false?: .missing
        case nil: .unknown
        }
    }
}

private struct CheckRow: View {
    enum State { case ok, missing, unknown, checking }

    let state: State
    let title: String
    var detail: String?
    var action: CheckAction?

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            icon
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                if let detail {
                    Text(detail).font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 8)
            if let action {
                Button(action.title, action: action.perform)
                    .buttonStyle(.borderedProminent)
                    .controlSize(.small)
            }
        }
    }

    @ViewBuilder
    private var icon: some View {
        switch state {
        case .ok: Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
        case .missing: Image(systemName: "xmark.circle.fill").foregroundStyle(.red)
        case .unknown: Image(systemName: "questionmark.circle.fill").foregroundStyle(.orange)
        case .checking: ProgressView().controlSize(.small)
        }
    }
}

struct CheckAction {
    let title: String
    let perform: () -> Void
}
