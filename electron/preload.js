const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('vexon', {
  getSettings: () => ipcRenderer.invoke('settings:get'),
  saveSettings: value => ipcRenderer.invoke('settings:save', value),
  scan: options => ipcRenderer.invoke('scan:run', options),
  cancel: () => ipcRenderer.invoke('task:cancel'),
  previewAI: id => ipcRenderer.invoke('ai:preview', id),
  analyze: options => ipcRenderer.invoke('ai:run', options),
  exportReport: id => ipcRenderer.invoke('report:export', id),
  onProgress: callback => {
    const listener = (_, data) => callback(data);
    ipcRenderer.on('scan:progress', listener);
    return () => ipcRenderer.removeListener('scan:progress', listener);
  }
});

