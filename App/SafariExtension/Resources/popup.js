// Popup of the toolbar button, also opened as a full page by background.js in place of a failed load.
// The PIN goes to the app's native handler, which shares it with the token extension (CryptoTokenKit).
const params = new URLSearchParams(location.search);
const isPage = params.has('page');
const returnURL = params.get('return');

const status = document.getElementById('status');
const form = document.getElementById('pin-form');
const pinInput = document.getElementById('pin');
const forget = document.getElementById('forget');
const back = document.getElementById('back');

const send = (message) => browser.runtime.sendNativeMessage('application.id', message);

if (isPage) {
  document.body.classList.add('page');
  if (returnURL) {
    document.getElementById('site').textContent = new URL(returnURL).host;
    document.getElementById('intro').hidden = false;
  }
}

function show(state) {
  const failure = state.failure && state.failureAge < 600 ? state.failure : (isPage ? params.get('reason') : null);
  if (state.pinShared) {
    const until = new Date(state.expires * 1000).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
    status.textContent = failure && failure !== 'Нужен PIN' ? failure : `PIN введён, действует до ${until}`;
    status.className = failure && failure !== 'Нужен PIN' ? 'warn' : 'ok';
    forget.hidden = false;
    back.hidden = !returnURL;
  } else {
    status.textContent = failure && failure !== 'Нужен PIN' ? `${failure}. Введите PIN` : 'Введите PIN токена';
    status.className = failure && failure !== 'Нужен PIN' ? 'warn' : '';
    forget.hidden = true;
    back.hidden = true;
  }
}

async function refresh() {
  try { show(await send({ action: 'status' })); }
  catch (e) { status.textContent = `Нет связи с приложением «Рутокен»: ${e}`; }
}

function returnToSite() {
  if (returnURL) location.replace(returnURL);
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const pin = pinInput.value;
  if (!pin) return;
  pinInput.value = '';
  const state = await send({ action: 'setPin', pin });
  show(state);
  browser.runtime.sendMessage({ type: 'pinChanged' }).catch(() => {});
  if (isPage) returnToSite();
});

forget.addEventListener('click', async () => {
  show(await send({ action: 'clearPin' }));
  browser.runtime.sendMessage({ type: 'pinChanged' }).catch(() => {});
});
back.addEventListener('click', returnToSite);

// Root certificate of the current site (or of the site that failed, on the PIN page).
document.getElementById('root').addEventListener('click', async () => {
  let site = returnURL;
  if (!site) {
    const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
    site = tab?.url;
  }
  const host = site && site.startsWith('https://') ? new URL(site).host : '';
  await browser.tabs.create({ url: browser.runtime.getURL(`root.html?site=${encodeURIComponent(host)}`) });
  window.close();
});

// All-sites access lets the background script notice sign-ins that failed for lack of a PIN.
const access = document.getElementById('access');
const allSites = { origins: ['https://*/*'] };
async function checkAccess() {
  let granted = null; // unknown without the permissions API
  try {
    if (browser.permissions?.contains) granted = await browser.permissions.contains(allSites);
  } catch (e) { /* unknown */ }
  access.hidden = granted !== false;
  // The popup reliably runs, so it also reports to the app's readiness checklist.
  send({ action: 'heartbeat', from: 'popup', allSites: granted, sawHTTPSPage: false }).catch(() => {});
}
document.getElementById('grant').addEventListener('click', async () => {
  try { await browser.permissions?.request?.(allSites); } catch (e) { /* ignored */ }
  await checkAccess();
  browser.runtime.sendMessage({ type: 'permissionsChanged' }).catch(() => {});
});

refresh();
checkAccess();
pinInput.focus();
