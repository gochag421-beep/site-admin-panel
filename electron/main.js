const { app, BrowserWindow, ipcMain, dialog, safeStorage, session } = require('electron');
const path = require('node:path');
const fs = require('node:fs/promises');
const { pathToFileURL } = require('node:url');
const { randomUUID } = require('node:crypto');
const { runScan } = require('../src/scanner');
const { analyzeWithOpenRouter } = require('../src/openrouter');
const { aiPayload } = require('../src/privacy');
const { createSettingsStore } = require('../src/settings');
let mainWindow, store, active = null, report = null;
const entry = path.join(__dirname, '../renderer/index.html');
const entryUrl = pathToFileURL(entry).href;
function trusted(event) {
  if (!mainWindow || mainWindow.isDestroyed() || event.sender !== mainWindow.webContents || event.senderFrame !== mainWindow.webContents.mainFrame || event.senderFrame.url !== entryUrl) throw new Error('Μη επιτρεπόμενη προέλευση αιτήματος.');
}
function handle(channel, callback) { ipcMain.handle(channel, async (event, value) => { trusted(event); return callback(value); }); }
function progress(data) { if (mainWindow && !mainWindow.isDestroyed()) mainWindow.webContents.send('scan:progress', data); }
async function task(fn) {
  if (active) throw new Error('Υπάρχει ήδη εργασία σε εξέλιξη.');
  const controller = new AbortController(); active = controller;
  try { return await fn(controller.signal); }
  finally { if (active === controller) active = null; }
}
function createWindow() {
  mainWindow = new BrowserWindow({ show: false, width: 1380, height: 880, minWidth: 900, minHeight: 680, backgroundColor: '#07111f', title: 'Vexon Security Scanner',
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false, sandbox: true } });
  mainWindow.webContents.on('will-navigate', event => event.preventDefault());
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  mainWindow.on('closed', () => { active?.abort(); mainWindow = null; });
  mainWindow.once('ready-to-show', () => { if (!process.argv.includes('--smoke-test')) mainWindow?.show(); });
  mainWindow.loadFile(entry);
}
app.whenReady().then(() => {
  store = createSettingsStore(path.join(app.getPath('userData'), 'settings.json'), safeStorage);
  session.defaultSession.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));
  session.defaultSession.setPermissionCheckHandler(() => false);
  createWindow();
});
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
app.on('activate', () => { if (!mainWindow) createWindow(); });
handle('settings:get', () => store.publicSettings());
handle('settings:save', value => store.save(value));
handle('task:cancel', () => { active?.abort(); return Boolean(active); });
handle('scan:run', options => task(async signal => {
  if (options?.authorized !== true) throw new Error('Επιβεβαίωσε ότι έχεις άδεια ελέγχου.');
  if (typeof options.url !== 'string' || options.url.length > 4096 || !Number.isInteger(options.maxPages) || options.maxPages < 1 || options.maxPages > 20) throw new Error('Μη έγκυρες επιλογές σάρωσης.');
  report = await runScan(options.url, { maxPages: options.maxPages, progress, signal });
  report.id = randomUUID(); report.authorizationConfirmed = true;
  progress({ stage: 'done', message: 'Η αναφορά είναι έτοιμη.', percent: 100 }); return report;
}));
function currentReport(id) { if (!report || id !== report.id) throw new Error('Η αναφορά άλλαξε. Χρησιμοποίησε την πιο πρόσφατη.'); return report; }
handle('ai:preview', id => aiPayload(currentReport(id)));
handle('ai:run', options => task(async signal => {
  if (options?.consent !== true) throw new Error('Χρειάζεται επιβεβαίωση αποστολής της αναφοράς.');
  const current = currentReport(options.id);
  if (!current.pagesScanned.length) throw new Error('Δεν υπάρχουν ελεγμένες σελίδες για AI ανάλυση.');
  const key = store.key(); if (!key) throw new Error('Πρόσθεσε OpenRouter API key στις Ρυθμίσεις.');
  try { current.ai = await analyzeWithOpenRouter(key, null, current, { signal, progress }); }
  catch (error) { current.ai = { error: error.message, attempts: error.attempts || [] }; }
  progress({ stage: 'done', message: 'Η AI εργασία ολοκληρώθηκε.', percent: 100 }); return current;
}));
handle('report:export', async id => {
  const current = currentReport(id);
  const result = await dialog.showSaveDialog(mainWindow, { defaultPath: 'vexon-report-' + new Date().toISOString().slice(0,10) + '.json', filters: [{ name: 'JSON report', extensions: ['json'] }] });
  if (result.canceled || !result.filePath) return null;
  await fs.writeFile(result.filePath, JSON.stringify(current, null, 2), 'utf8'); return result.filePath;
});

