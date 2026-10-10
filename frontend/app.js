const byId = id => document.getElementById(id);
const backend = byId('backend'), token = byId('token'), status = byId('status');
const chain = byId('chain'), events = byId('events');
const smithproxyUrl = byId('smithproxy-url'), smithproxyKey = byId('smithproxy-key');
const smithproxyVerify = byId('smithproxy-verify'), configureStatus = byId('configure-status');
let revision = 0, timer;

backend.value = localStorage.getItem('spider-backend') || backend.value;
token.value = sessionStorage.getItem('spider-token') || '';
smithproxyUrl.value = localStorage.getItem('smithproxy-url') || smithproxyUrl.value;
smithproxyVerify.checked = localStorage.getItem('smithproxy-verify') !== 'false';

const baseUrl = () => backend.value.replace(/\/$/, '');
const headers = () => ({'X-Spider-Token': token.value});

async function poll() {
  try {
    const response = await fetch(`${baseUrl()}/api/events?after=${revision}`, {headers: headers()});
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    revision = data.revision;
    for (const record of data.events) {
      const event = record.event;
      if (event.action === 'spider-smithproxy-status') {
        chain.textContent = `PC frontend       connected\nSpider backend    connected\nSmithproxy API    ${event.state}\n${event.detail || ''}`;
      }
      if (event.action === 'ping') chain.textContent += `\nWebhook callback received from ${event.source || 'Smithproxy'}`;
      events.textContent = `r${record.revision} ${JSON.stringify(event, null, 2)}\n\n${events.textContent}`;
    }
    status.textContent = `live · r${revision}`;
    status.className = 'ok';
  } catch (error) {
    status.textContent = `offline · ${error.message}`;
    status.className = 'error';
  }
}

function connect() {
  localStorage.setItem('spider-backend', backend.value);
  sessionStorage.setItem('spider-token', token.value);
  revision = 0;
  events.textContent = '';
  clearInterval(timer);
  poll();
  timer = setInterval(poll, 1000);
}

async function configureSmithproxy() {
  configureStatus.textContent = 'connecting…';
  configureStatus.className = '';
  try {
    const response = await fetch(`${baseUrl()}/api/config/smithproxy`, {
      method: 'POST',
      headers: {...headers(), 'Content-Type': 'application/json'},
      body: JSON.stringify({url: smithproxyUrl.value, api_key: smithproxyKey.value,
                            verify_tls: smithproxyVerify.checked}),
    });
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
    localStorage.setItem('smithproxy-url', smithproxyUrl.value);
    localStorage.setItem('smithproxy-verify', smithproxyVerify.checked);
    smithproxyKey.value = '';
    configureStatus.textContent = 'configuration accepted';
    configureStatus.className = 'ok';
  } catch (error) {
    configureStatus.textContent = error.message;
    configureStatus.className = 'error';
  }
}

byId('connect').onclick = connect;
byId('configure').onclick = configureSmithproxy;
connect();
