// Finds the root CA of a site through the native handler and offers it as a configuration profile.
// The user must compare the fingerprint with the one from IT: the root comes over an untrusted connection.
const params = new URLSearchParams(location.search);
const siteInput = document.getElementById('site');
const status = document.getElementById('status');
const result = document.getElementById('result');
let profile = null;
let rootName = 'root';

siteInput.value = params.get('site') ?? '';

async function find() {
  const site = siteInput.value.trim();
  if (!site) return;
  result.hidden = true;
  status.className = '';
  status.textContent = 'Проверяем сертификат сайта…';
  let reply;
  try {
    reply = await browser.runtime.sendNativeMessage('application.id', { action: 'findRoot', site });
  } catch (e) {
    reply = { error: `Нет связи с приложением «Рутокен»: ${e}` };
  }
  if (reply.error) {
    status.textContent = reply.error;
    status.className = 'warn';
    return;
  }
  status.textContent = '';
  rootName = reply.name;
  profile = reply.profile;
  document.getElementById('name').textContent = reply.name;
  document.getElementById('until').textContent = new Date(reply.notAfter * 1000).toLocaleDateString('ru-RU', { year: 'numeric', month: 'long', day: 'numeric' });
  document.getElementById('chain').textContent = reply.chain.join(' → ');
  const from = reply.downloadedFrom;
  document.getElementById('from').textContent = from;
  document.getElementById('from').hidden = document.getElementById('from-label').hidden = !from;
  const anchors = document.getElementById('anchors');
  anchors.textContent = reply.anchors ? '✓ Подтверждает сертификат этого сайта' : '✗ НЕ подтверждает сертификат этого сайта — не устанавливайте';
  anchors.className = reply.anchors ? 'ok' : 'bad';
  document.getElementById('download').hidden = !reply.anchors;
  const bytes = reply.fingerprint.split(':');
  const rows = [];
  for (let i = 0; i < bytes.length; i += 8) rows.push(bytes.slice(i, i + 8).join(' '));
  document.getElementById('fingerprint').textContent = rows.join('\n');
  result.hidden = false;
}

document.getElementById('site-form').addEventListener('submit', (event) => { event.preventDefault(); find(); });

document.getElementById('download').addEventListener('click', () => {
  if (!profile) return;
  const bytes = Uint8Array.from(atob(profile), (c) => c.charCodeAt(0));
  const blob = new Blob([bytes], { type: 'application/x-apple-aspen-config' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = `${rootName}.mobileconfig`;
  document.body.appendChild(link);
  link.click();
  link.remove();
});

document.getElementById('open-app').addEventListener('click', () => {
  location.href = `rutoken://root?site=${encodeURIComponent(siteInput.value.trim())}`;
});

if (siteInput.value) find();
