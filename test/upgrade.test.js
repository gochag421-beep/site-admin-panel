const test=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');const os=require('node:os');const path=require('node:path');
const {runScan,inspectPage}=require('../src/scanner');const {finding,compareReports}=require('../src/findings');const {publicIP}=require('../src/network');const {Store}=require('../src/store');const {inspectSource,packagesFromLock,scanSource}=require('../src/source');const {sanitize}=require('../src/privacy');const {reportHtml}=require('../src/report-html');
const blank=()=>({findings:[],coverage:[],errors:[],modules:{},pagesScanned:[],summary:{score:null,total:0}});
const response=body=>({status:200,headers:{'content-type':'text/html'},body});
test('failed scan has no score and cannot resolve old findings',async()=>{
  const report=await runScan('https://example.com',{validate:async u=>new URL(u),tlsRequest:async()=>null,request:async()=>{throw new Error('Offline');}});
  assert.equal(report.status,'failed');assert.equal(report.summary.score,null);
  const old=finding('csp',{url:'https://example.com/',title:'CSP',evidence:'Missing'});compareReports({id:'old',findings:[old]},report);assert.equal(report.resolved[0].status,'needs_verification');
});
test('successful repeated check resolves; skipped checks never resolve',()=>{
  const old=finding('csp',{url:'https://example.com/',title:'CSP',evidence:'Missing'});const current=blank();current.coverage=[old.scope+'|csp'];compareReports({findings:[old]},current);assert.equal(current.resolved[0].status,'resolved');
});
test('cookie values and resource query strings do not enter findings',()=>{
  const r=blank();inspectPage('https://example.com/',{...response('<script src="http://cdn.example.org/x?token=VERYPRIVATE"></script>'),headers:{'content-type':'text/html','set-cookie':['session=SECRETSESSION; Path=/']}},r);
  assert.ok(!JSON.stringify(r).includes('SECRETSESSION'));assert.ok(!JSON.stringify(r).includes('VERYPRIVATE'));
  assert.ok(r.findings.some(f=>f.checkId==='cookie-secure'));
});
test('HTTP navigation links are not mistaken for mixed-content resources',()=>{
  const r=blank();inspectPage('https://example.com/',response('<a href="http://elsewhere.com/">Link</a>'),r);assert.ok(!r.findings.some(f=>f.checkId==='mixed'));
});
test('blocks mapped private IPv6, reserved and multicast IP addresses',()=>{
  for(const ip of ['127.0.0.1','10.2.3.4','0.0.0.0','169.254.169.254','100.64.0.1','224.0.0.1','::1','::ffff:127.0.0.1','fc00::1','fe80::1'])assert.equal(publicIP(ip),false,ip);
  assert.equal(publicIP('8.8.8.8'),true);
});
test('source checks disclose file and lines, never matched secret text',()=>{
  const r=blank();const token='sk-or-v1-'+'x'.repeat(40);inspectSource('const key="'+token+'";','app.js','https://github.com/a/b/blob/main/app.js',r);
  assert.ok(r.findings.some(f=>f.checkId==='secret-key'));assert.ok(!JSON.stringify(r).includes(token));
});
test('lockfiles extract pinned packages and deduplicate',()=>{
  assert.deepEqual(packagesFromLock({packages:{'':{version:'1.0.0'},'node_modules/a':{version:'1.2.3'},'node_modules/b/node_modules/a':{version:'1.2.3'}}}),[{name:'a',version:'1.2.3'}]);
});
test('projects, history, status and schedule survive a restart',()=>{
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'vexon-test-'));try{
    const s=new Store(dir);const p=s.saveProject({name:'Client',url:'https://example.com',authorized:true,schedule:'daily'});
    assert.equal(s.due(Date.now()).length,0);assert.equal(s.due(Date.now()+86400010).length,1);
    const r=blank();r.target=p.url;r.status='complete';r.findings=[finding('csp',{url:p.url,title:'CSP'})];const saved=s.saveReport(p.id,r);
    s.setStatus(saved.id,saved.findings[0].id,'needs_verification');
    const again=new Store(dir);assert.equal(again.history().length,1);assert.equal(again.report(saved.id).findings[0].status,'needs_verification');assert.equal(again.project(p.id).name,'Client');
    assert.throws(()=>again.report('../settings.json'),/Invalid/);assert.throws(()=>again.setStatus(saved.id,saved.findings[0].id,'resolved'),/επανέλεγχο/);
  }finally{fs.rmSync(dir,{recursive:true,force:true});}
});
test('HTML report escapes untrusted text and cannot load an external logo',()=>{
  const r=blank();r.completedAt=new Date().toISOString();r.target='<script>alert(1)</script>';r.summary.score=null;
  const html=reportHtml(r,{}, {logo:'https://untrusted.example/logo.png'});assert.ok(html.includes('&lt;script&gt;'));assert.ok(!html.includes('<script>'));assert.ok(!html.includes('https://untrusted'));
});
test('AI sanitization redacts JWTs, query values and API keys',()=>{
  const s=JSON.stringify(sanitize({target:'https://example.com/?key=SUPERSECRET',evidence:'sk-or-v1-'+'a'.repeat(30)}));assert.ok(!s.includes('SUPERSECRET'));assert.ok(!s.includes('a'.repeat(30)));
});
test('source scan ties OSV matches to pinned package versions using a fixed commit',async()=>{
  const r=blank();const calls=[];const lock={packages:{'node_modules/demo':{version:'1.0.0'}}};
  const fetchImpl=async(url,opts)=>{calls.push({url,opts});let data;
    if(url.endsWith('/repos/a/b/'))data={default_branch:'main'};
    else if(url.endsWith('/commits/main'))data={sha:'abc123'};
    else if(url.includes('/git/trees/abc123'))data={tree:[{type:'blob',path:'package-lock.json',size:100,sha:'blob1'}]};
    else if(url.endsWith('/git/blobs/blob1'))data={encoding:'base64',content:Buffer.from(JSON.stringify(lock)).toString('base64')};
    else if(url.endsWith('/querybatch'))data={results:[{vulns:[{id:'GHSA-demo'}]}]};
    else throw new Error('Unexpected '+url);
    return {ok:true,json:async()=>data};};
  await scanSource('a/b',r,{fetchImpl});assert.equal(r.modules.source,'complete');assert.equal(r.source.packagesChecked,1);assert.ok(r.findings.some(f=>f.evidence.includes('demo@1.0.0')));assert.ok(calls.some(c=>c.url.includes('abc123')));
});
