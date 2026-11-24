// No npm packages required. Run with Node >= 22 and an installed Chromium:
// node tests/wifi_map_browser.cjs C:\path\to\chrome.exe
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { spawn } = require('node:child_process');

const browserPath = process.argv[2];
if (!browserPath || !fs.existsSync(browserPath)) {
  throw new Error('Pass the path to an installed Chromium executable. No packages will be installed.');
}
const root = path.resolve(__dirname, '..');
const output = path.join(root, 'target', 'wifi-map-browser');
fs.mkdirSync(output, { recursive: true });
const maliciousName = '<img src=x onerror="window.__xss=true">';
const device = (ip, role, kind, hostname) => ({
  ip, role, kind, hostname, mac: '02:00:00:00:00:01',
  evidence: role === 'peer' ? 'Low confidence: hostname suggests a type; not verified.' : 'Local interface or routing evidence.',
  observation: 'Cached neighbor; may be stale', distance_m: null,
});
let fixture = {
  busy: false, error: null,
  report: {
    ssid: 'Documentation network', bssid: '02:00:00:00:00:01', interface: 'Wi-Fi',
    local_ip: '192.0.2.17', prefix: 24, signal_percent: 75,
    scanned_at: new Date().toISOString(), elapsed_ms: 200, active: false, can_scan: true,
    devices: [device('192.0.2.17', 'local', 'Computer', 'demo-workstation'),
      device('192.0.2.1', 'gateway', 'Gateway', null),
      device('192.0.2.20', 'peer', 'Printer', 'office-printer'),
      device('192.0.2.21', 'peer', 'Unknown', maliciousName)],
    warnings: ['Physical distances are unavailable. Placement is schematic.'],
  },
};
const posts = [], errors = [], externalRequests = [];
const server = http.createServer((request, response) => {
  response.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'nonce-unlatched-map'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'");
  if (request.url === '/') {
    response.setHeader('Content-Type', 'text/html; charset=utf-8');
    return response.end(fs.readFileSync(path.join(root, 'src', 'wifi_map.html')));
  }
  if (request.headers['x-unlatched-map'] !== '1') { response.writeHead(403); return response.end(); }
  response.setHeader('Content-Type', 'application/json');
  if (request.url === '/api/state') return response.end(JSON.stringify(fixture));
  if (request.method === 'POST' && ['/api/scan', '/api/refresh'].includes(request.url)) {
    posts.push(request.url);
    fixture.report.active = request.url === '/api/scan';
    fixture.report.scanned_at = new Date().toISOString();
    fixture.report.devices[2].observation = fixture.report.active ? 'ICMP reply this scan' : 'Cached neighbor; may be stale';
    response.writeHead(202); return response.end('{"accepted":true}');
  }
  response.writeHead(404); response.end('{}');
});

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
let browser, socket;
async function run() {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  browser = spawn(browserPath, [
    '--headless', '--disable-gpu', '--remote-debugging-port=0',
    `--user-data-dir=${path.join(output, 'profile')}`, '--no-first-run', '--no-default-browser-check',
    '--disable-background-networking', '--disable-component-update', '--disable-sync',
    '--disable-extensions', '--disable-features=Translate,OptimizationHints', 'about:blank',
  ], { windowsHide: true, stdio: ['ignore', 'ignore', 'pipe'] });
  const wsUrl = await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Chromium startup timed out')), 20000);
    let stderr = '';
    browser.on('error', error => { clearTimeout(timeout); reject(error); });
    browser.on('exit', code => { clearTimeout(timeout); reject(new Error(`Chromium exited: ${code}`)); });
    browser.stderr.on('data', chunk => {
      stderr = (stderr + chunk.toString()).slice(-20000);
      const match = stderr.match(/DevTools listening on (ws:\/\/[^\s]+)/);
      if (match) { clearTimeout(timeout); resolve(match[1]); }
    });
  });
  socket = new WebSocket(wsUrl);
  await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });
  let sequence = 0;
  const waiting = new Map();
  socket.onmessage = event => {
    const message = JSON.parse(event.data);
    if (message.id && waiting.has(message.id)) {
      const { resolve, reject, timeout } = waiting.get(message.id);
      waiting.delete(message.id); clearTimeout(timeout);
      message.error ? reject(new Error(JSON.stringify(message.error))) : resolve(message.result);
    }
    if (message.method === 'Runtime.exceptionThrown') errors.push(message.params.exceptionDetails.text);
    if (message.method === 'Log.entryAdded' && message.params.entry.level === 'error') errors.push(message.params.entry.text);
    if (message.method === 'Network.requestWillBeSent' && !message.params.request.url.startsWith(origin)) externalRequests.push(message.params.request.url);
  };
  const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
    const id = ++sequence;
    const timeout = setTimeout(() => { waiting.delete(id); reject(new Error(`CDP timeout: ${method}`)); }, 10000);
    waiting.set(id, { resolve, reject, timeout });
    socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
  });
  const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
  const command = (method, params) => send(method, params, sessionId);
  const evaluate = async expression => {
    const result = await command('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
    if (result.exceptionDetails) throw new Error(result.exceptionDetails.text);
    return result.result.value;
  };
  const until = async expression => {
    const deadline = Date.now() + 10000;
    while (Date.now() < deadline) { if (await evaluate(expression)) return; await sleep(100); }
    throw new Error(`Browser assertion timed out: ${expression}`);
  };
  for (const domain of ['Page', 'Runtime', 'Log', 'Network']) await command(`${domain}.enable`);
  await command('Emulation.setDeviceMetricsOverride', { width: 1440, height: 1000, deviceScaleFactor: 1, mobile: false });
  await command('Page.navigate', { url: origin });
  await until("document.querySelector('#count')?.textContent === '4' && !document.querySelector('#scan').disabled");
  assert.equal(posts.length, 0, 'Loading the page must not trigger active discovery');
  assert.equal(await evaluate("document.querySelectorAll('.device').length"), 4);
  await evaluate("document.querySelector('#search').value='printer'; document.querySelector('#search').dispatchEvent(new Event('input'))");
  assert.equal(await evaluate("document.querySelectorAll('.device').length"), 1);
  await evaluate("document.querySelector('#search').value=''; document.querySelector('#search').dispatchEvent(new Event('input')); [...document.querySelectorAll('.device')].at(-1).click()");
  assert.equal(await evaluate("document.querySelector('#details h2').textContent"), maliciousName);
  assert.equal(await evaluate("Boolean(window.__xss) || document.querySelectorAll('#details img, #device-list img').length > 0"), false);
  assert.match(await evaluate("document.querySelector('#details').textContent"), /DistanceUnavailable/);
  await evaluate("[...document.querySelectorAll('.device')].find(button=>button.textContent.includes('office-printer')).click()");
  assert.match(await evaluate("document.querySelector('#details').textContent"), /Likely Printer/);
  const yaw = await evaluate('yaw');
  await evaluate("document.querySelector('#map').dispatchEvent(new KeyboardEvent('keydown',{key:'ArrowRight'}))");
  assert.notEqual(await evaluate('yaw'), yaw, 'Keyboard orbit changes the camera');
  const zoom = await evaluate('zoom');
  await evaluate("document.querySelector('#zoom-in').click()");
  assert.ok(await evaluate('zoom') > zoom, 'Zoom changes the camera');
  await evaluate("document.querySelector('#scan').click()");
  await until("report.active && document.querySelector('#replies').textContent === '1' && !document.querySelector('#scan').disabled");
  assert.deepEqual(posts, ['/api/scan']);
  await evaluate("document.querySelector('#refresh').click()");
  await until("!report.active && !document.querySelector('#refresh').disabled");
  assert.deepEqual(posts, ['/api/scan', '/api/refresh']);
  const desktop = await command('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync(path.join(output, 'desktop.png'), Buffer.from(desktop.data, 'base64'));
  await command('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 1, mobile: true });
  await sleep(150);
  assert.equal(await evaluate('document.documentElement.scrollWidth <= window.innerWidth'), true, 'Mobile view fits the viewport');
  const mobile = await command('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true });
  fs.writeFileSync(path.join(output, 'mobile.png'), Buffer.from(mobile.data, 'base64'));
  fixture.error = 'Fixture telemetry unavailable';
  await until("!document.querySelector('#error').hidden");
  assert.match(await evaluate("document.querySelector('#error').textContent"), /Fixture telemetry unavailable/);
  fixture.error = null; fixture.report.can_scan = false; fixture.report.scanned_at = new Date().toISOString();
  await until("document.querySelector('#scan').disabled && !document.querySelector('#refresh').disabled");
  assert.deepEqual(errors, [], 'No JavaScript or CSP errors');
  assert.deepEqual(externalRequests, [], 'No external requests');
  console.log('PASS: desktop/mobile layout, selection, filtering, honest distances, safe text rendering, orbit, zoom, explicit scan/refresh, errors, and disabled scan.');
  console.log('Screenshots: target/wifi-map-browser/desktop.png and mobile.png (fictional documentation addresses only).');
}
run().catch(error => { console.error(error.message); process.exitCode = 1; }).finally(async () => {
  if (socket?.readyState === WebSocket.OPEN) socket.close();
  if (browser && browser.exitCode === null) {
    browser.kill();
    await Promise.race([new Promise(resolve => browser.once('exit', resolve)), sleep(3000)]);
  }
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
});
