const {contextBridge,ipcRenderer}=require('electron');
contextBridge.exposeInMainWorld('vexon',{
  chat:id=>ipcRenderer.invoke('chat:get',id),
  sendChat:(id,text)=>ipcRenderer.invoke('chat:send',id,text),
  openSource:url=>ipcRenderer.invoke('source:open',url),
  onChat:fn=>ipcRenderer.on('chat:message',(_,data)=>fn(data)),
  workspace:()=>ipcRenderer.invoke('workspace:get'),
  saveProject:p=>ipcRenderer.invoke('project:save',p),
  scan:id=>ipcRenderer.invoke('scan:run',id),
  cancel:()=>ipcRenderer.invoke('scan:cancel'),
  report:id=>ipcRenderer.invoke('report:get',id),
  status:(id,fid,status)=>ipcRenderer.invoke('finding:status',id,fid,status),
  saveSettings:s=>ipcRenderer.invoke('settings:save',s),
  pickLogo:()=>ipcRenderer.invoke('brand:logo'),
  exportReport:(id,format)=>ipcRenderer.invoke('report:export',id,format),
  onProgress:fn=>ipcRenderer.on('scan:progress',(_,data)=>fn(data)),
  onFinished:fn=>ipcRenderer.on('scan:finished',(_,data)=>fn(data))
});
