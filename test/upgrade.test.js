const test=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');const os=require('node:os');const path=require('node:path');
const {runScan,inspectPage}=require('../src/scanner');const {finding,compareReports}=require('../src/findings');const {publicIP}=require('../src/network');const {Store}=require('../src/store');const {inspectSource,packagesFromLock,scanSource}=require('../src/source');const {sanitize}=require('../src/privacy');const {reportHtml}=require('../src/report-html');const {osvDetails,nvdRecords,searchCVEs}=require('../src/cve');const {directIntent,chooseIntent}=require('../src/chat');
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
    s.addChat(p.id,'user','Έλεγξε SSL');s.saveResearch(p.id,{query:'nginx',items:[]});
    const again=new Store(dir);assert.equal(again.history().length,1);assert.equal(again.report(saved.id).findings[0].status,'needs_verification');assert.equal(again.project(p.id).name,'Client');assert.equal(again.chat(p.id)[0].text,'Έλεγξε SSL');assert.equal(again.research(p.id).query,'nginx');
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
    else if(url.endsWith('/vulns/GHSA-demo'))data={id:'GHSA-demo',aliases:['CVE-2026-12345'],summary:'Demo advisory',database_specific:{severity:'HIGH'},severity:[{type:'CVSS_V3',score:'CVSS:3.1/AV:N'}],affected:[{package:{name:'demo'},ranges:[{events:[{fixed:'1.0.1'}]}]}]};
    else throw new Error('Unexpected '+url);
    return {ok:true,json:async()=>data};};
  await scanSource('a/b',r,{fetchImpl});assert.equal(r.modules.source,'complete');assert.equal(r.source.packagesChecked,1);assert.ok(r.findings.some(f=>f.evidence.includes('demo@1.0.0')));assert.equal(r.findings[0].vulnerability.cves[0],'CVE-2026-12345');assert.ok(calls.some(c=>c.url.includes('abc123')));
});
test('CVE details keep exact OSV package matching distinct from NVD candidates',async()=>{
  const detail=osvDetails({id:'GHSA-x',aliases:['CVE-2025-9999'],affected:[{package:{name:'demo'},ranges:[{events:[{fixed:'2.0.0'}]}]}],severity:[{type:'CVSS_V3',score:'CVSS:3.1/AV:N'}]},'demo');
  assert.deepEqual(detail.cves,['CVE-2025-9999']);assert.deepEqual(detail.fixes,['2.0.0']);
  const records=nvdRecords({vulnerabilities:[{cve:{id:'CVE-2025-9999',vulnStatus:'Analyzed',descriptions:[{lang:'en',value:'Candidate only'}],metrics:{cvssMetricV31:[{cvssData:{baseScore:8.1,baseSeverity:'HIGH',vectorString:'CVSS:3.1/X'}}]}}}]});assert.equal(records[0].match,'candidate');
  const result=await searchCVEs('demo',{fetchImpl:async()=>({ok:true,json:async()=>({totalResults:1,vulnerabilities:[]})})});assert.equal(result.total,1);assert.equal(result.items.length,0);
});
test('Greeklish chat commands are deterministic and AI plans remain allowlisted',async()=>{
  assert.deepEqual(directIntent('κανε scan για CVE'),{action:'scan_cve'});assert.deepEqual(directIntent('ψάξε CVE για nginx'),{action:'search_cve',query:'nginx'});assert.deepEqual(directIntent('σταμάτα'),{action:'cancel'});
  const plan=await chooseIntent('anything',async()=>({text:'{"action":"terminal","command":"bad"}'}));assert.deepEqual(plan,{action:'explain'});
});
