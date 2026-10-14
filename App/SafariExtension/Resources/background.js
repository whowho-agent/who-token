// Hints for signing in with the USB token: a badge when no PIN is entered, and a PIN page in place of
// Safari's "can't establish a secure connection" when a site needed the token but couldn't get it.
const api = globalThis.browser;

/** A token problem recorded by the token extension within this many seconds explains a failed load. */
const FAILURE_WINDOW = 60;
/** Don't replace the same site's error page again sooner than this (ms). */
const PROMPT_INTERVAL = 60 * 1000;

async function nativeStatus() {
  try {
    return await api.runtime.sendNativeMessage('application.id', { action: 'status' });
  } catch (e) {
    return null;
  }
}

async function updateBadge(status) {
  status = status ?? await nativeStatus();
  const needsPin = status && !status.pinShared;
  try {
    await api.action.setBadgeText({ text: needsPin ? '!' : '' });
    await api.action.setBadgeBackgroundColor?.({ color: '#C62828' });
  } catch (e) { /* badges are optional on some Safari versions */ }
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
  await updateBadge(status);
  const problem = tokenProblem(status);
  if (!problem) return;

  const host = new URL(details.url).host;
  const key = `prompted:${host}`;
  const { [key]: last } = await api.storage.local.get(key);
  if (last && Date.now() - last < PROMPT_INTERVAL) return;
  await api.storage.local.set({ [key]: Date.now() });

  const page = api.runtime.getURL('popup.html') +
    `?page=1&return=${encodeURIComponent(details.url)}&reason=${encodeURIComponent(problem)}`;
  await api.tabs.update(details.tabId, { url: page });
});

api.tabs.onActivated.addListener(() => updateBadge());
api.webNavigation.onCompleted.addListener((details) => { if (details.frameId === 0) updateBadge(); });
api.runtime.onMessage.addListener((message) => { if (message?.type === 'pinChanged') updateBadge(); });
updateBadge();
