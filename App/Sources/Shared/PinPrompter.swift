import Foundation
import Observation
import SwiftUI

struct PinRequest: Identifiable {
    let id = UUID()
    let tokenLabel: String
    let retriesLeft: Int?
}

/// Single place that asks the user for the token PIN; presented as a sheet by the root view.
@MainActor @Observable
final class PinPrompter {
    var request: PinRequest?
    private var continuation: CheckedContinuation<String?, Never>?

    func ask(_ request: PinRequest) async -> String? {
        // Only one prompt at a time; a pending one is cancelled.
        continuation?.resume(returning: nil)
        return await withCheckedContinuation { continuation in
            self.continuation = continuation
            self.request = request
        }
    }

    func submit(_ pin: String?) {
        request = nil
        continuation?.resume(returning: pin)
        continuation = nil
    }
}

struct PinEntrySheet: View {
    let request: PinRequest
    let onSubmit: (String?) -> Void
    @State private var pin = ""
    @FocusState private var focused: Bool

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    // Rutoken PINs may contain letters, so a full ASCII keyboard is required.
                    SecureField("PIN пользователя", text: $pin)
                        .keyboardType(.asciiCapable)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .focused($focused)
                        .onSubmit { if !pin.isEmpty { onSubmit(pin) } }
                        .submitLabel(.go)
                } footer: {
                    if let left = request.retriesLeft {
                        Text("Осталось попыток: \(left)")
                    }
                }
            }
            .navigationTitle(request.tokenLabel)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Отмена") { onSubmit(nil) }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Войти") { onSubmit(pin) }.disabled(pin.isEmpty)
                }
            }
            .onAppear { focused = true }
        }
        .presentationDetents([.medium])
        .interactiveDismissDisabled()
    }
}
