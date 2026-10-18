// Hints for signing in with the USB token: a badge when no PIN is entered, and a PIN page in place of
// Safari's "can't establish a secure connection" when a site needed the token but couldn't get it.
// Only on the organization's sites listed in the app: elsewhere a failed load is just a network error.
const api = globalThis.browser;

/** A token problem recorded by the token extension within this many seconds explains a failed load. */
const FAILURE_WINDOW = 60;
/** Don't replace the same site's error page again sooner than this (ms). */
const PROMPT_INTERVAL = 60 * 1000;

/** Diagnostics (kept by the native side in Debug builds only): token problems per site. */
function log(text) {
  api.runtime.sendNativeMessage('application.id', { action: 'log', text }).catch(() => {});
}

async function nativeStatus() {
  try {
    return await api.runtime.sendNativeMessage('application.id', { action: 'status' });
  } catch (e) {
    return null;
  }
}

/** "!" on the toolbar button of a tab showing one of the token sites while no PIN is entered. */
async function updateBadge(status, tabId, url) {
  try {
    if (tabId === undefined || url === undefined) {
      const [tab] = await api.tabs.query({ active: true, currentWindow: true });
      if (!tab) return;
      tabId = tab.id;
      url = tab.url ?? '';
    }
    status = status ?? await nativeStatus();
    let host = '';
    try { host = new URL(url).hostname; } catch (e) { /* not a web page */ }
    const needsPin = status && !status.pinShared && isTokenSite(status, host);
    await api.action.setBadgeText({ text: needsPin ? '!' : '', tabId });
    await api.action.setBadgeBackgroundColor?.({ color: '#C62828' });
  } catch (e) { /* badges are optional on some Safari versions */ }
}

/** The host is one of the sites set in the app, or a subdomain of one. */
function isTokenSite(status, host) {
  const sites = status?.sites ?? [];
  host = host.toLowerCase();
  return sites.some((domain) => host === domain || host.endsWith('.' + domain));
}

function tokenProblem(status) {
  if (!status) return null;
  if (status.failure && status.failureAge < FAILURE_WINDOW) return status.failure;
  if (!status.pinShared) return 'Нужен PIN';
  return null;
}

api.webNavigation.onErrorOccurred.addListener(async (details) => {
  if (details.frameId !== 0 || !details.url.startsWith('https://')) return;
  const status = await nativeStatus();
  await updateBadge(status, details.tabId, details.url);
  const host = new URL(details.url).hostname;
  if (!isTokenSite(status, host)) return;
  const problem = tokenProblem(status);
  if (!problem) return;

  const key = `prompted:${host}`;
  const { [key]: last } = await api.storage.local.get(key);
  if (last && Date.now() - last < PROMPT_INTERVAL) return;
  await api.storage.local.set({ [key]: Date.now() });

  log(`token needed for ${host}: ${problem}`);
  const page = api.runtime.getURL('pin.html') +
    `?page=1&return=${encodeURIComponent(details.url)}&reason=${encodeURIComponent(problem)}`;
  // Safari won't show an extension page in place of its own error page, so open a new tab and close
  // the failed one: after the PIN the new tab goes on to the original address.
  await api.tabs.create({ url: page });
  await api.tabs.remove(details.tabId).catch(() => {});
});

/** Tells the app the extension is enabled and whether it may read https sites (for its checklist). */
let lastHeartbeat = 0;
async function heartbeat(sawHTTPSPage = false) {
  if (!sawHTTPSPage && Date.now() - lastHeartbeat < 30 * 1000) return;
  lastHeartbeat = Date.now();
  let allSites = null; // unknown when Safari doesn't expose the permissions API
  try {
    if (api.permissions?.contains) allSites = await api.permissions.contains({ origins: ['https://*/*'] });
  } catch (e) { /* stays unknown */ }
  api.runtime.sendNativeMessage('application.id', { action: 'heartbeat', from: 'background', allSites, sawHTTPSPage })
    .catch(() => {});
}

api.tabs.onActivated.addListener(() => { updateBadge(); heartbeat(); });
api.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId !== 0) return;
  updateBadge(null, details.tabId, details.url);
  // Receiving this event for an https page proves access to that site.
  heartbeat(details.url.startsWith('https://'));
});
api.runtime.onMessage.addListener((message) => {
  if (message?.type === 'pinChanged') updateBadge();
  if (message?.type === 'permissionsChanged') { lastHeartbeat = 0; heartbeat(); }
});
updateBadge();
heartbeat();
