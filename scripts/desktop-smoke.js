// Runs in Electron, including on the Windows build runner. No external website scans.
const {app,BrowserWindow}=require('electron');const fs=require('node:fs');const os=require('node:os');const path=require('node:path');const assert=require('node:assert/strict');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'vexon-desktop-'));app.setPath('userData',temp);
require('../electron/main');
const timeout=setTimeout(()=>{console.error('Desktop test timed out');app.exit(1);},60000);
app.whenReady().then(async()=>{
  let win;for(let i=0;i<100;i++){win=BrowserWindow.getAllWindows().find(w=>w.webContents.getURL().includes('index.html'));if(win&&!win.webContents.isLoading())break;await new Promise(r=>setTimeout(r,100));}
  try{
    assert.ok(win);const run=code=>win.webContents.executeJavaScript(code,true);
    await run('window.vexon.workspace()');
    const project=await run(`window.vexon.saveProject({name:'Desktop QA',client:'Test client',url:'http://127.0.0.1',authorized:true,browser:false,useAI:false,schedule:'off'})`);
    const report=await run(`window.vexon.scan(${JSON.stringify(project.id)})`);assert.equal(report.status,'failed');assert.equal(report.summary.score,null);
    const state=await run('window.vexon.workspace()');assert.equal(state.history.length,1);
    await run(`window.vexon.sendChat(${JSON.stringify(project.id)},'κατάσταση')`);
    const chat=await run(`window.vexon.chat(${JSON.stringify(project.id)})`);assert.equal(chat.messages.length,2);assert.match(chat.messages[1].text,/σάρωση/);
    await run(`document.querySelector('#chatProject').value=${JSON.stringify(project.id)};document.querySelector('#chatProject').dispatchEvent(new Event('change'));show('chat')`);await new Promise(r=>setTimeout(r,200));
    assert.equal(await run(`document.querySelector('#chat').hidden`),false);
    const loaded=await run(`window.vexon.report(${JSON.stringify(report.id)})`);assert.equal(loaded.id,report.id);
    await run(`renderReport(${JSON.stringify(report)});show('report')`);assert.equal(await run(`document.querySelector('#report').hidden`),false);
    await run('refresh();show("overview")');await new Promise(r=>setTimeout(r,300));
    fs.mkdirSync(path.join(__dirname,'../tmp/qa'),{recursive:true});
    fs.writeFileSync(path.join(__dirname,'../tmp/qa/dashboard.png'),(await win.webContents.capturePage()).toPNG());
    const {finding}=require('../src/findings');
    const fixture={...report,target:'https://example.gr/',status:'complete',pagesScanned:['https://example.gr/'],errors:[],findings:[],summary:{score:78,total:8,counts:{critical:0,high:0,medium:4,low:4,info:0}}};
    for(let i=0;i<8;i++)fixture.findings.push(finding('fixture'+i,{url:'https://example.gr/services',title:i%2?'Cookie χωρίς ρητό SameSite':'Content Security Policy απουσιάζει',severity:i%2?'low':'medium',evidence:'Συγκεκριμένη παρατήρηση στην απόκριση HTTP. Οι ευαίσθητες τιμές δεν αποθηκεύονται.',recommendation:'Έλεγξε τη ρύθμιση στον server, εφάρμοσε την προτεινόμενη αλλαγή και εκτέλεσε νέο έλεγχο για επιβεβαίωση.'}));
    await run(`renderReport(${JSON.stringify(fixture)});show('report')`);
    const {createPDF}=require('../electron/pdf');const pdf=await createPDF(fixture,{name:'Δοκιμαστική εταιρική ιστοσελίδα',client:'Πελάτης επίδειξης'},{company:'VEXON · Ασφάλεια ιστοσελίδων',logo:'data:image/png;base64,'+fs.readFileSync(path.join(__dirname,'../renderer/icon.png')).toString('base64')});assert.equal(pdf.subarray(0,4).toString(),'%PDF');
    fs.mkdirSync(path.join(__dirname,'../tmp/qa'),{recursive:true});fs.writeFileSync(path.join(__dirname,'../tmp/qa/desktop-smoke.pdf'),pdf);
    const image=await win.webContents.capturePage();fs.writeFileSync(path.join(__dirname,'../tmp/qa/desktop-smoke.png'),image.toPNG());
    console.log('DESKTOP PASS: preload, IPC, project save, failed scan, history, report UI and PDF.');clearTimeout(timeout);app.exit(0);
  }catch(e){console.error(e);clearTimeout(timeout);app.exit(1);}
});
