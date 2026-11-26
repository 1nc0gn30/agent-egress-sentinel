const { app, BrowserWindow, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const http = require('http');
const { spawn } = require('child_process');

// Opt-in only sandbox disable for constrained CI containers
if (process.env.ELECTRON_NO_SANDBOX === '1') {
  app.commandLine.appendSwitch('no-sandbox');
  app.commandLine.appendSwitch('disable-gpu-sandbox');
}
app.commandLine.appendSwitch('disable-dev-shm-usage');

const IS_SMOKE = process.argv.includes('--smoke-test');
const TOOL_ID = 'agent-egress-sentinel';
const TOOL_NAME = 'Agent Egress Sentinel';
const BACKEND_PORT = Number(process.env.PORT || 8095);
const PROXY_PORT = Number(process.env.PROXY_PORT || 8195);
const BACKEND_URL = `http://127.0.0.1:${BACKEND_PORT}`;
const HEALTH_URL = `${BACKEND_URL}/health`;

let mainWindow = null;
let backendProcess = null;
let spawnedByElectron = false;
const consoleErrors = [];

function isBackendRunning() {
  return new Promise((resolve) => {
    const req = http.get(HEALTH_URL, (res) => {
      let body = '';
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => {
        if (res.statusCode !== 200) {
          resolve(false);
          return;
        }
        try {
          const parsed = JSON.parse(body);
          resolve(parsed && parsed.status === 'ok' && parsed.service === TOOL_ID);
        } catch (_e) {
          resolve(false);
        }
      });
    });
    req.on('error', () => resolve(false));
    req.setTimeout(1500, () => {
      req.destroy();
      resolve(false);
    });
  });
}

function startBackend() {
  const rootDir = path.resolve(__dirname, '..');
  const env = { ...process.env, PORT: String(BACKEND_PORT), PYTHONUNBUFFERED: '1' };
  const serverPy = path.join(rootDir, 'server.py');
  let args = ['server.py', '--web-port', String(BACKEND_PORT), '--proxy-port', String(PROXY_PORT)];

  if (!fs.existsSync(serverPy)) {
    const srcDir = path.join(rootDir, 'src');
    env.PYTHONPATH = env.PYTHONPATH ? `${srcDir}:${env.PYTHONPATH}` : srcDir;
    args = ['-m', 'agent_egress_sentinel.cli', 'serve', '--web-port', String(BACKEND_PORT), '--proxy-port', String(PROXY_PORT)];
  }

  backendProcess = spawn('python3', args, {
    cwd: rootDir,
    stdio: 'ignore',
    detached: false,
    env,
  });
  spawnedByElectron = true;
}

function stopOwnedBackend() {
  if (spawnedByElectron && backendProcess && !backendProcess.killed) {
    try {
      backendProcess.kill('SIGTERM');
    } catch (_e) {}
    backendProcess = null;
    spawnedByElectron = false;
  }
}

async function waitForBackend(maxAttempts = 35, interval = 200) {
  for (let i = 0; i < maxAttempts; i++) {
    if (await isBackendRunning()) return true;
    await new Promise((r) => setTimeout(r, interval));
  }
  return false;
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 920,
    minWidth: 1024,
    minHeight: 700,
    show: !IS_SMOKE,
    backgroundColor: '#08080B',
    title: `${TOOL_NAME} v2.6.0 // ZothOS Sovereign Workstation (:${BACKEND_PORT})`,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
    },
    autoHideMenuBar: true,
  });

  mainWindow.webContents.on('console-message', (_event, level, message) => {
    if (level >= 3 && !message.includes('favicon')) {
      consoleErrors.push(message);
    }
  });

  if (IS_SMOKE) {
    const timer = setTimeout(() => {
      stopOwnedBackend();
      console.log(JSON.stringify({ tool: TOOL_ID, port: BACKEND_PORT, ok: false, error: 'timeout' }));
      app.exit(1);
    }, 12000);

    mainWindow.webContents.once('did-finish-load', async () => {
      clearTimeout(timer);
      try {
        await new Promise((r) => setTimeout(r, 400));
        const metrics = await mainWindow.webContents.executeJavaScript(`({
          title: document.title || '',
          h1Count: document.querySelectorAll('h1').length,
          textLen: (document.body && document.body.innerText ? document.body.innerText.trim().length : 0),
          buttons: document.querySelectorAll('button, a, input, select, canvas').length,
          hasRadar: Boolean(document.getElementById('radarCanvas')),
          hasRules: Boolean(document.getElementById('policyRulesSection'))
        })`);
        const ok =
          metrics.h1Count >= 1 &&
          metrics.textLen > 100 &&
          metrics.hasRadar &&
          metrics.hasRules &&
          consoleErrors.length === 0;
        console.log(JSON.stringify({
          tool: TOOL_ID,
          name: TOOL_NAME,
          port: BACKEND_PORT,
          proxyPort: PROXY_PORT,
          url: BACKEND_URL,
          ok,
          ...metrics,
          consoleErrors: consoleErrors.slice(0, 5),
        }));
        stopOwnedBackend();
        app.exit(ok ? 0 : 1);
      } catch (err) {
        stopOwnedBackend();
        console.log(JSON.stringify({ tool: TOOL_ID, port: BACKEND_PORT, ok: false, error: String(err) }));
        app.exit(1);
      }
    });
  }

  mainWindow.loadURL(BACKEND_URL);

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('http:') || url.startsWith('https:')) {
      shell.openExternal(url);
    }
    return { action: 'deny' };
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

app.whenReady().then(async () => {
  if (!(await isBackendRunning())) {
    startBackend();
    await waitForBackend();
  }
  createWindow();
});

app.on('will-quit', () => {
  stopOwnedBackend();
});

app.on('window-all-closed', () => {
  stopOwnedBackend();
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
