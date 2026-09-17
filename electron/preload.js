const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('vexon', {
  getSettings: () => ipcRenderer.invoke('settings:get'),
  saveSettings: (settings) => ipcRenderer.invoke('settings:save', settings),
  scan: (options) => ipcRenderer.invoke('scan:run', options),
  exportReport: (report) => ipcRenderer.invoke('report:export', report),
  onProgress: (callback) => ipcRenderer.on('scan:progress', (_, data) => callback(data))
});
