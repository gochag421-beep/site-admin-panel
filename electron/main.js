const { app, BrowserWindow, ipcMain, dialog, safeStorage } = require('electron');
const path = require('node:path');
const fs = require('node:fs');
const { runScan } = require('../src/scanner');
const { analyzeWithOpenRouter, selectFreeModel } = require('../src/openrouter');

let mainWindow;
const settingsPath = () => path.join(app.getPath('userData'), 'settings.json');

function readSettings() {
  try {
    const data = JSON.parse(fs.readFileSync(settingsPath(), 'utf8'));
    if (data.apiKeyEncrypted && safeStorage.isEncryptionAvailable()) {
      data.apiKey = safeStorage.decryptString(Buffer.from(data.apiKeyEncrypted, 'base64'));
    }
    delete data.apiKeyEncrypted;
    return data;
  } catch { return { maxPages: 10, useAI: true }; }
}

function writeSettings(value) {
  const clean = { maxPages: Math.min(20, Math.max(1, Number(value.maxPages) || 10)), useAI: Boolean(value.useAI) };
  if (value.apiKey) {
    if (!safeStorage.isEncryptionAvailable()) throw new Error('Secure Windows credential encryption is unavailable.');
    clean.apiKeyEncrypted = safeStorage.encryptString(value.apiKey.trim()).toString('base64');
  }
  fs.mkdirSync(path.dirname(settingsPath()), { recursive: true });
  fs.writeFileSync(settingsPath(), JSON.stringify(clean, null, 2), { mode: 0o600 });
  return { ...clean, hasApiKey: Boolean(clean.apiKeyEncrypted), apiKeyEncrypted: undefined };
}

function createWindow() {
  mainWindow = new BrowserWindow({ width: 1380, height: 880, minWidth: 1050, minHeight: 720, backgroundColor: '#07111f', title: 'Vexon Security Scanner', webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false, sandbox: true } });
  mainWindow.loadFile(path.join(__dirname, '../renderer/index.html'));
}

app.whenReady().then(createWindow);
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });

ipcMain.handle('settings:get', () => { const s = readSettings(); return { ...s, apiKey: '', hasApiKey: Boolean(s.apiKey) }; });
ipcMain.handle('settings:save', (_, value) => writeSettings(value));
ipcMain.handle('scan:run', async (_, options) => {
  if (!options?.authorized) throw new Error('You must confirm authorization for this website.');
  const progress = (data) => mainWindow?.webContents.send('scan:progress', data);
  const report = await runScan(options.url, { maxPages: options.maxPages, progress });
  const settings = readSettings();
  if (options.useAI && settings.apiKey) {
    progress({ stage: 'ai', message: 'Selecting an available free OpenRouter model…', percent: 84 });
    try {
      const model = await selectFreeModel(settings.apiKey);
      report.ai = await analyzeWithOpenRouter(settings.apiKey, model, report);
      report.ai.model = model;
    } catch (error) { report.ai = { error: error.message }; }
  }
  progress({ stage: 'done', message: 'Scan complete', percent: 100 });
  return report;
});
ipcMain.handle('report:export', async (_, report) => {
  const result = await dialog.showSaveDialog({ defaultPath: `vexon-report-${new Date().toISOString().slice(0,10)}.json`, filters: [{ name: 'JSON report', extensions: ['json'] }] });
  if (result.canceled || !result.filePath) return null;
  fs.writeFileSync(result.filePath, JSON.stringify(report, null, 2));
  return result.filePath;
});
