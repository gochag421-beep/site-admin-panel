const {app,BrowserWindow,ipcMain,dialog,safeStorage,Notification,Tray,Menu,nativeImage,shell}=require('electron');
const path=require('node:path');const fs=require('node:fs');const {pathToFileURL}=require('node:url');
const {runScan}=require('../src/scanner');const {scanBrowser}=require('./browser-scan');const {scanSource,parseRepo}=require('../src/source');
const {summarize}=require('../src/findings');const {sanitize}=require('../src/privacy');const {Store,atomic}=require('../src/store');
const {analyzeWithOpenRouter}=require('../src/openrouter');const {createPDF}=require('./pdf');
let win,tray,store,busy=false,controller,timer,quitting=false,live='Αναμονή',activeProjectId=null;
const index=pathToFileURL(path.join(__dirname,'../renderer/index.html')).href;
const settingsFile=()=>path.join(app.getPath('userData'),'settings.json');
function rawSettings(){try{return JSON.parse(fs.readFileSync(settingsFile(),'utf8'));}catch{return {};}}
function secret(name){const raw=rawSettings();const encrypted=raw[name+'Encrypted'];if(encrypted&&safeStorage.isEncryptionAvailable())return safeStorage.decryptString(Buffer.from(encrypted,'base64'));return '';}
function settings(){const raw=rawSettings();return {company:raw.company||'VEXON',contact:raw.contact||'',logo:raw.logo||'',launchAtLogin:Boolean(raw.launchAtLogin),notifications:raw.notifications!==false,hasApiKey:Boolean(raw.apiKeyEncrypted),hasGithubToken:Boolean(raw.githubTokenEncrypted)};}
function saveSettings(value){const raw=rawSettings();for(const name of ['apiKey','githubToken']){
    if(value['clear'+name])delete raw[name+'Encrypted'];
    else if(value[name]?.trim()) {if(!safeStorage.isEncryptionAvailable())throw new Error('Η ασφαλής αποθήκευση κλειδιών δεν είναι διαθέσιμη.');raw[name+'Encrypted']=safeStorage.encryptString(String(value[name]).trim()).toString('base64');}
  }
  raw.company=String(value.company||'VEXON').slice(0,120);raw.contact=String(value.contact||'').slice(0,200);raw.notifications=value.notifications!==false;raw.launchAtLogin=Boolean(value.launchAtLogin);
  if(process.platform==='win32'&&app.isPackaged)app.setLoginItemSettings({openAtLogin:raw.launchAtLogin,args:['--hidden']});
  atomic(settingsFile(),raw);return settings();
}
function emit(channel,data){if(win&&!win.isDestroyed())win.webContents.send(channel,data);}
function progress(data){live=data.message;emit('scan:progress',{...data,projectId:activeProjectId});}
function notify(title,body){if(settings().notifications&&Notification.isSupported()){const n=new Notification({title,body});n.on('click',()=>{win.show();win.focus();});n.show();}}
async function runProject(id,{scheduled=false,mode='full'}={}){
  if(busy)throw new Error('Υπάρχει σάρωση σε εξέλιξη.');const project={...store.project(id)};if(!project.authorized)throw new Error('Δεν υπάρχει επιβεβαίωση εξουσιοδότησης.');
  busy=true;activeProjectId=id;controller=new AbortController();const signal=controller.signal;let report;
  try{
    progress({stage:'start',percent:1,message:`Σάρωση: ${project.name}`});
    const login=scheduled?null:require('./upgrades').sessionFor(project);
    const request=login?async(url,options)=>{const u=new URL(url);if(u.origin!==login.origin||/logout|signout|delete|remove|unsubscribe/i.test(u.pathname))throw new Error('Login scan: η διαδρομή δεν επιτρέπεται.');return require('../src/network').getPage(url,{...options,cookie:login.cookies.map(c=>c.name+'='+c.value).join('; ')});}:undefined;
    report=await runScan(project.url,{maxPages:mode==='http'||mode==='cve'?1:project.maxPages,progress,signal,request});
    report.authContext=login?login.context:'public';if(login)report.errors.push({module:'session',error:'Χρησιμοποιήθηκε προσωρινό cookie. Η εγκυρότητα του login χρειάζεται επιβεβαίωση· εξαρτήσεις και τρίτα origins δεν λαμβάνουν cookies.'});
    if((mode==='browser'||(mode==='full'&&project.browser))&&!signal.aborted&&report.pagesScanned.length)await scanBrowser(report,{signal,progress,cookies:login?.cookies||[]});
    if(project.repository&&['full','cve'].includes(mode)&&!signal.aborted)await scanSource(project.repository,report,{token:secret('githubToken'),signal,progress});
    if(mode==='full'&&!signal.aborted)await require('../src/verify').verifyObservations(report,{request,signal,progress});
    report.mode=mode;
    if(project.wordpress&&!signal.aborted){report.wordpressResearch=[];for(const component of (report.wordpress||[]).slice(0,5)){if(signal.aborted)break;try{progress({stage:'wordpress',percent:76,message:'WordPress CVE: '+component.slug});const research=await require('../src/cve').searchCVEs(component.type==='core'?'WordPress':'WordPress '+component.slug,{signal});report.wordpressResearch.push({...research,component});}catch(e){report.errors.push({module:'wordpress',error:String(e.message)});}}}
    if(mode==='cve'&&!signal.aborted){
      report.cveCandidates=[];
      for(const tech of (report.technologies||[]).slice(0,3)){
        try{progress({stage:'cve',percent:78,message:'NVD: '+tech.name+' '+(tech.version||'')});const result=await require('../src/cve').searchCVEs(tech.name,{signal});report.cveCandidates.push({...result,detected:tech});}
        catch(e){report.errors.push({module:'cve',error:String(e.message)});}
      }
      if(!project.repository)report.errors.push({module:'cve',error:'Δεν συνδέθηκε repository. Τα αποτελέσματα NVD είναι μόνο υποψήφια. Για ακριβή σύγκριση εξαρτήσεων σύνδεσε repository με package-lock.json.'});
      if(!project.repository&&!report.technologies?.length)report.errors.push({module:'cve',error:'Δεν αναγνωρίστηκαν τεχνολογίες. Μπορείς να ζητήσεις από το chat αναζήτηση για συγκεκριμένο προϊόν ή CVE ID.'});
    }
    if(project.useAI&&!signal.aborted&&report.pagesScanned.length){
      const apiKey=secret('apiKey');
      if(apiKey){progress({stage:'ai',percent:84,message:'Ανάλυση ευρημάτων…'});try{
        report.ai=await analyzeWithOpenRouter(apiKey,null,sanitize(report),{progress,signal,fetchImpl:(url,opts)=>fetch(url,{...opts,signal:AbortSignal.any([signal,opts.signal].filter(Boolean))})});
      }catch(e){report.ai={error:signal.aborted?'Η AI ανάλυση ακυρώθηκε.':String(e.message)};}}
      else report.ai={error:'Δεν έχει αποθηκευτεί OpenRouter API key.'};
    }
    report.project={name:project.name,client:project.client,url:project.url};report.cancelled=signal.aborted;summarize(report);report=store.saveReport(id,report);
    const expiry=report.tls?.validTo&&new Date(report.tls.validTo)-Date.now()<30*86400000;
    if(scheduled||report.comparison.new||expiry)notify('Vexon · '+project.name,`${report.comparison.new} νέα ευρήματα. ${expiry?'Το πιστοποιητικό χρειάζεται ανανέωση.':''} ${report.status==='failed'?'Η σάρωση απέτυχε.':''}`);
    emit('scan:finished',report);return report;
  }finally{busy=false;controller=null;progress({stage:'done',percent:100,message:'Η εργασία ολοκληρώθηκε.'});activeProjectId=null;}
}
async function tick(){if(busy)return;const due=store.due()[0];if(!due)return;store.advance(due.id);try{await runProject(due.id,{scheduled:true});}catch{notify('Vexon · Σάρωση δεν ολοκληρώθηκε',due.name);}}
function handle(name,fn){ipcMain.handle(name,(event,...args)=>{if(event.sender!==win.webContents)throw new Error('Untrusted IPC sender');return fn(...args);});}
function setupIPC(){
  require('./upgrades').setupUpgrades({handle,store,win:()=>win,isBusy:()=>busy,notify,emit,getProfile:settings,restoreProfile:p=>{const raw=rawSettings();raw.company=String(p.company||'VEXON').slice(0,120);raw.contact=String(p.contact||'').slice(0,200);raw.notifications=p.notifications!==false;if(typeof p.logo==='string'&&p.logo.length<2_000_000&&/^data:image\/png;base64,[A-Za-z0-9+/=]+$/.test(p.logo))raw.logo=p.logo;atomic(settingsFile(),raw);}});
  require('./chat-controller').setupChat({handle,store,getKey:()=>secret('apiKey'),runProject,isBusy:()=>busy,getLive:()=>live,cancel:()=>controller?.abort(),emit});
  handle('source:open',async value=>{const u=new URL(value);if(u.protocol!=='https:'||!['nvd.nist.gov','osv.dev'].includes(u.hostname)||u.username||u.password)throw new Error('Επιτρέπονται μόνο επίσημοι σύνδεσμοι NVD / OSV.');await shell.openExternal(u.href);});
  handle('workspace:get',()=>({projects:store.list(),history:store.history(),settings:settings(),busy}));
  handle('project:save',p=>{if(busy)throw new Error('Περίμενε να ολοκληρωθεί η σάρωση.');if(p.repository)p.repository=parseRepo(p.repository);return store.saveProject(p);});
  handle('scan:run',id=>runProject(id));handle('scan:cancel',()=>{controller?.abort();return true;});
  handle('report:get',id=>store.report(id));handle('finding:status',(id,fid,status)=>store.setStatus(id,fid,status));
  handle('settings:save',saveSettings);
  handle('brand:logo',async()=>{const result=await dialog.showOpenDialog(win,{filters:[{name:'Logo',extensions:['png','jpg','jpeg']}],properties:['openFile']});if(result.canceled)return null;
    const file=result.filePaths[0];if(fs.statSync(file).size>5_000_000)throw new Error('Μέγιστο αρχείο 5 MB.');const img=nativeImage.createFromPath(file);if(img.isEmpty())throw new Error('Μη έγκυρη εικόνα.');
    const raw=rawSettings();raw.logo=img.resize({width:400}).toDataURL();atomic(settingsFile(),raw);return raw.logo;});
  handle('report:export',async(id,format)=>{const r=store.report(id);const project=r.project||store.project(r.projectId);format=format==='pdf'?'pdf':'json';
    const result=await dialog.showSaveDialog(win,{defaultPath:`Vexon-${new Date(r.completedAt).toISOString().slice(0,10)}-${r.id.slice(0,8)}.${format}`,filters:[{name:format.toUpperCase(),extensions:[format]}]});
    if(result.canceled)return null;const data=format==='pdf'?await createPDF(r,project,settings()):JSON.stringify(r,null,2);fs.writeFileSync(result.filePath,data);return result.filePath;
  });
}
if(!app.requestSingleInstanceLock())app.quit();else{
  app.on('second-instance',()=>{win?.show();win?.focus();});
  app.whenReady().then(()=>{
    app.setAppUserModelId('gr.vexon.securityscanner');store=new Store(app.getPath('userData'));
    win=new BrowserWindow({width:1450,height:960,minWidth:1050,minHeight:720,show:!process.argv.includes('--hidden'),backgroundColor:'#0a1220',title:'Vexon Security Scanner',webPreferences:{preload:path.join(__dirname,'preload.js'),sandbox:true,nodeIntegration:false,contextIsolation:true}});
    win.webContents.setWindowOpenHandler(()=>({action:'deny'}));win.webContents.on('will-navigate',e=>e.preventDefault());
    setupIPC();win.loadURL(index);
    tray=new Tray(nativeImage.createFromPath(path.join(__dirname,'../renderer/icon.png')));tray.setToolTip('Vexon Security Scanner · Οι σαρώσεις παραμένουν ενεργές');
    tray.setContextMenu(Menu.buildFromTemplate([{label:'Άνοιγμα Vexon',click:()=>win.show()},{label:'Έξοδος',click:()=>app.quit()}]));tray.on('double-click',()=>win.show());
    win.on('close',e=>{if(!quitting){e.preventDefault();win.hide();}});
    timer=setInterval(tick,60000);setTimeout(tick,10000);
  }).catch(e=>{dialog.showErrorBox('Vexon',String(e.message));app.quit();});
}
app.on('before-quit',()=>{quitting=true;clearInterval(timer);controller?.abort();});
