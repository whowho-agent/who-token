const list = document.getElementById('resources');
function mark(name, ok) {
  const li = document.createElement('li');
  li.textContent = `${ok ? '✓' : '✗'} ${name}`;
  li.className = ok ? 'ok' : 'fail';
  list.appendChild(li);
}
mark('app.js', true);
mark('style.css', getComputedStyle(document.body).backgroundColor === 'rgb(245, 245, 247)');
const img = document.querySelector('h1 img');
img.complete ? mark('logo.svg', img.naturalWidth > 0) : img.addEventListener('load', () => mark('logo.svg', true));
img.addEventListener('error', () => mark('logo.svg', false));

fetch('/whoami').then(r => r.json())
  .then(j => { document.getElementById('whoami').textContent = JSON.stringify(j, null, 2); mark('fetch /whoami', true); })
  .catch(e => { document.getElementById('whoami').textContent = String(e); mark('fetch /whoami', false); });

const xhr = new XMLHttpRequest();
xhr.open('GET', 'data.json');
xhr.onload = () => { document.getElementById('data').textContent = xhr.responseText; mark('XHR data.json', xhr.status === 200); };
xhr.onerror = () => mark('XHR data.json', false);
xhr.send();
