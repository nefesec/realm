const { app, BrowserWindow, Tray, Menu, nativeImage, Notification, ipcMain, session } = require('electron');
const path = require('path');
const { spawn } = require('child_process');

// Linux: enable media device access
if (process.platform === 'linux') {
  app.commandLine.appendSwitch('enable-features', 'AudioContextAutoplayByUserActivation,WebRTCPipeWireCapturer');
  app.commandLine.appendSwitch('use-fake-ui-for-media-stream'); // bypass PipeWire permission UI
  app.commandLine.appendSwitch('ignore-certificate-errors');   // self-signed cert localhost
}
const http = require('http');

const fs = require('fs');
const PORT = process.env.PORT || 3002;
const certExists = fs.existsSync(path.join(__dirname, '..', 'server', 'certs', 'cert.pem'));
const SERVER_URL = `${certExists ? 'https' : 'http'}://localhost:${PORT}`;

// ── EMBEDDED SERVER ──────────────────────────────────────────
// Spawn the server as a child process (avoids native module recompilation)
let serverProc = null;
function startServer() {
  const serverDir = path.join(__dirname, '..', 'server');
  serverProc = spawn('node', ['server.js'], {
    cwd: serverDir,
    env: { ...process.env },
    stdio: 'pipe',
  });
  serverProc.stdout.on('data', d => console.log('[server]', d.toString().trim()));
  serverProc.stderr.on('data', d => console.error('[server]', d.toString().trim()));
  serverProc.on('exit', code => console.log('[server] exited', code));
}

app.on('before-quit', () => { if (serverProc) serverProc.kill(); });

startServer();

// ── INSTANCE UNIQUE ──────────────────────────────────────────
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) { app.quit(); process.exit(0); }

let win  = null;
let tray = null;

app.on('second-instance', () => { win?.show(); win?.focus(); });

// ── FENÊTRE PRINCIPALE ──────────────────────────────────────
function createWindow() {
  win = new BrowserWindow({
    width: 1100, height: 720,
    minWidth: 800, minHeight: 500,
    title: 'Realm',
    backgroundColor: '#09090b',
    show: false,
    webPreferences: {
      preload:          path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration:  false,
      webSecurity:      false,
      sandbox:          true,
    },
  });

  win.loadURL(SERVER_URL);
  win.setMenuBarVisibility(false);
  win.webContents.on('console-message', (e, level, msg) => { if (level >= 2) console.error('[renderer]', msg); });

  // Security: block external navigation
  win.webContents.on('will-navigate', (e, url) => {
    if (!url.startsWith(SERVER_URL)) e.preventDefault();
  });
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));

  const showTimer = setTimeout(() => win?.show(), 2000);
  win.webContents.once('did-finish-load', () => { clearTimeout(showTimer); win.show(); });

  let retries = 0;
  win.webContents.on('did-fail-load', (_, code) => {
    if (code === -3) return;
    if (retries < 10) {
      retries++;
      setTimeout(() => win?.loadURL(SERVER_URL), 2000);
    } else {
      win.show();
    }
  });

  win.on('close', (e) => {
    if (!app.isQuiting) { e.preventDefault(); win.hide(); }
  });
}

// ── TRAY ─────────────────────────────────────────────────────
function createTray() {
  const b64 =
    'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABHNCSVQICAgIfAhkiAAAAAlwSFlz' +
    'AAALEwAACxMBAJqcGAAAAB10RVh0Q29tbWVudABDcmVhdGVkIHdpdGggR0lNUGQuZQcAAAA2SURB' +
    'VDiNY2RgYPj/n4GBAQgYGIgzgBhKIwMYDKgBgzEMqBODMcxQGsGgTgyGOjFIhTIAAD5NBBEx6XEV' +
    'AAAAAElFTkSuQmCC';

  let icon;
  try { icon = nativeImage.createFromBuffer(Buffer.from(b64, 'base64')); }
  catch { icon = nativeImage.createEmpty(); }

  try { tray = new Tray(icon); } catch { return; }

  tray.setToolTip('Realm');
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: 'Ouvrir Realm', click: () => { win?.show(); win?.focus(); } },
    { type: 'separator' },
    { label: 'Quitter',    click: () => { app.isQuiting = true; app.quit(); } },
  ]));
  tray.on('click', () => {
    if (win) win.isVisible() ? win.focus() : win.show();
  });
}

// ── IPC ──────────────────────────────────────────────────────
ipcMain.on('notify', (_, { title, body }) => {
  if (!Notification.isSupported()) return;
  const n = new Notification({ title, body });
  n.on('click', () => { win?.show(); win?.focus(); });
  n.show();
});

// ── START ────────────────────────────────────────────────────
// Allow self-signed cert for localhost
app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {
  if (url.startsWith('https://localhost') || url.startsWith('https://127.0.0.1')) {
    event.preventDefault();
    callback(true);
  } else {
    callback(false);
  }
});

app.whenReady().then(() => {
  // Grant media permissions before window creation
  session.defaultSession.setPermissionRequestHandler((wc, permission, cb) => cb(true));
  session.defaultSession.setPermissionCheckHandler(() => true);
  session.defaultSession.setDevicePermissionHandler(() => true);
  createTray();
  createWindow();
});

app.on('window-all-closed', () => { /* reste dans le tray */ });
