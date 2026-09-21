const {BrowserWindow,session}=require('electron');const {randomUUID}=require('node:crypto');
const {startBrowserProxy}=require('../src/network');const {finding}=require('../src/findings');const {safeUrl}=require('../src/privacy');
async function scanBrowser(report,{signal,progress=()=>{}}={}){
  report.modules.browser='running';report.browser={pages:[],blockedRequests:0,failedRequests:0};
  const proxy=await startBrowserProxy();const sess=session.fromPartition('scan-'+randomUUID(),{cache:false});let win;
  try{
    await sess.setProxy({proxyRules:`http=127.0.0.1:${proxy.port};https=127.0.0.1:${proxy.port}`,proxyBypassRules:'<-loopback>'});
    sess.setPermissionRequestHandler((_wc,_permission,callback)=>callback(false));sess.setPermissionCheckHandler(()=>false);
    sess.on('will-download',(event)=>event.preventDefault());
    const pages=report.pagesScanned.filter(u=>!u.includes('REDACTED')).slice(0,3);const origins=new Set(pages.map(u=>new URL(u).origin));let budget=0;let active='';let failed=0;
    sess.webRequest.onBeforeRequest((details,callback)=>{
      const url=details.url;const allowed=/^https?:/.test(url)&&['GET','HEAD'].includes(details.method)&&!['webSocket','ping'].includes(details.resourceType)&&++budget<=300;
      let mainAllowed=true;try{if(details.resourceType==='mainFrame')mainAllowed=origins.has(new URL(url).origin);}catch{mainAllowed=false;}
      if(!allowed||!mainAllowed){report.browser.blockedRequests++;return callback({cancel:true});}callback({});
    });
    const add=(id,title,evidence,subject='')=>{if(!active||report.findings.filter(f=>f.module==='browser').length>=80)return;report.findings.push(finding(id,{module:'browser',scope:`browser:${active}`,url:active,title,severity:'low',kind:'observed',evidence,subject,recommendation:'Αναπαρήγαγε το πρόβλημα στον browser και έλεγξε το Network/Console. Μπορεί να οφείλεται σε τρίτο πάροχο ή στον περιορισμένο έλεγχο.'}));};
    sess.webRequest.onErrorOccurred(details=>{if(details.error!=='net::ERR_BLOCKED_BY_CLIENT'&&active){failed++;add('browser-network','Αποτυχημένο browser request',`${details.error}; ${safeUrl(details.url)}`,safeUrl(details.url));}});
    sess.webRequest.onCompleted(details=>{if(details.statusCode>=400){failed++;add('browser-http','Πόρος επέστρεψε HTTP σφάλμα',`HTTP ${details.statusCode}; ${safeUrl(details.url)}`,safeUrl(details.url));}});
    win=new BrowserWindow({show:false,webPreferences:{session:sess,sandbox:true,nodeIntegration:false,contextIsolation:true,webSecurity:true,allowRunningInsecureContent:false,backgroundThrottling:false}});
    win.webContents.setWindowOpenHandler(()=>({action:'deny'}));
    win.webContents.on('will-attach-webview',event=>event.preventDefault());
    win.webContents.on('console-message',(details)=>{if(details?.level==='error'||details?.level===3){
      // Store location only: console text may contain session tokens or personal data.
      add('browser-console','JavaScript / console error',`Error στη γραμμή ${details.lineNumber||'?'} του ${safeUrl(details.sourceId||active)}. Το μήνυμα αποκρύπτεται για προστασία δεδομένων.`,safeUrl(details.sourceId||active)+':'+(details.lineNumber||'?'));
    }});
    const abort=()=>{if(win&&!win.isDestroyed())win.destroy();};signal?.addEventListener('abort',abort,{once:true});
    try{for(const page of pages){if(signal?.aborted)break;active=page;progress({stage:'browser',percent:55,message:`Chromium: ${new URL(page).pathname}`});
      let timer;try{await Promise.race([win.loadURL(page),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('Browser navigation timeout')),18000);})]);
        await new Promise(r=>setTimeout(r,2500));
        report.browser.pages.push(page);
        for(const id of ['browser-network','browser-http','browser-console'])report.coverage.push(`browser:${page}|${id}`);
      }catch{report.errors.push({module:'browser',url:page,error:'Η φόρτωση δεν ολοκληρώθηκε. Τα ευρήματα χρειάζονται επιβεβαίωση.'});}
      finally{clearTimeout(timer);if(!win.isDestroyed())win.webContents.stop();active='';}
    }}finally{signal?.removeEventListener('abort',abort);}
    report.browser.failedRequests=failed;report.modules.browser=report.errors.some(e=>e.module==='browser')?'partial':'complete';
    if(report.browser.blockedRequests){report.modules.browser='partial';report.errors.push({module:'browser',error:`${report.browser.blockedRequests} requests μπλοκαρίστηκαν από το read-only προφίλ. Η δυναμική κάλυψη είναι περιορισμένη.`});
      // Absence under blocked execution cannot prove remediation.
      report.coverage=report.coverage.filter(c=>!c.startsWith('browser:'));
    }
  }catch{report.modules.browser='failed';report.errors.push({module:'browser',error:'Ο browser έλεγχος δεν ολοκληρώθηκε.'});}
  finally{if(win&&!win.isDestroyed())win.destroy();await sess.closeAllConnections();await sess.clearStorageData();proxy.close();}
}
module.exports={scanBrowser};
