// The PIN goes to the app's native handler, which shares it with the token extension (CryptoTokenKit).
const status = document.getElementById('status');
const form = document.getElementById('pin-form');
const pinInput = document.getElementById('pin');
const forget = document.getElementById('forget');

const send = (message) => browser.runtime.sendNativeMessage('application.id', message);

function show(state) {
  if (state.pinShared) {
    const until = new Date(state.expires * 1000).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
    status.textContent = `PIN введён, действует до ${until}`;
    status.className = 'ok';
    forget.hidden = false;
  } else {
    status.textContent = 'Введите PIN токена';
    status.className = '';
    forget.hidden = true;
  }
}

async function refresh() {
  try { show(await send({ action: 'status' })); }
  catch (e) { status.textContent = `Нет связи с приложением: ${e}`; }
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const pin = pinInput.value;
  if (!pin) return;
  pinInput.value = '';
  show(await send({ action: 'setPin', pin }));
});

forget.addEventListener('click', async () => show(await send({ action: 'clearPin' })));

refresh();
