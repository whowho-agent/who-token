import SwiftUI
import TokenKit

/// The organization's sites that sign in with the token. The Safari extension offers the PIN page and
/// shows its badge only there, so an unreachable site elsewhere stays an ordinary Safari error.
struct SitesView: View {
    @Bindable var model: SetupModel
    @State private var text = ""
    @FocusState private var focused: Bool

    var body: some View {
        Form {
            Section {
                TextField("wiki.example.com, mail.example.com", text: $text, axis: .vertical)
                    .lineLimit(3...8)
                    .keyboardType(.URL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .focused($focused)
            } header: {
                Text("Домены через запятую")
            } footer: {
                Text("Поддомены входят автоматически: example.com включает wiki.example.com. На остальных сайтах расширение ничего не делает — PIN по-прежнему можно ввести кнопкой «Рутокен» в Safari.")
            }
            let parsed = TokenSites.parse(text)
            if !parsed.isEmpty {
                Section("Будет работать на") {
                    ForEach(parsed, id: \.self) { Text($0) }
                }
            }
        }
        .navigationTitle("Сайты")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("Готово") {
                    model.saveSites(text)
                    focused = false
                }
                .disabled(TokenSites.parse(text) == model.sites)
            }
        }
        .onAppear {
            text = model.sites.joined(separator: ", ")
            // Suggest the site checked for the root certificate.
            if text.isEmpty { text = TokenSites.parse(model.workSite).first ?? "" }
            if text.isEmpty { focused = true }
        }
        // Leaving with the back button keeps what was typed.
        .onDisappear { model.saveSites(text) }
    }
}
