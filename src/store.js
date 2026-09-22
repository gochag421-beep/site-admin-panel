const fs=require('node:fs');const path=require('node:path');const {randomUUID}=require('node:crypto');
const {compareReports}=require('./findings');
function atomic(file,data){fs.mkdirSync(path.dirname(file),{recursive:true});const temp=file+'.tmp';fs.writeFileSync(temp,JSON.stringify(data,null,2),{mode:0o600});fs.renameSync(temp,file);}
class Store {
  constructor(dir){this.dir=dir;this.file=path.join(dir,'workspace-v2.json');this.data={projects:[],reports:[]};if(fs.existsSync(this.file))this.data=JSON.parse(fs.readFileSync(this.file,'utf8'));}
  commit(){atomic(this.file,this.data);}
  list(){return this.data.projects.map(p=>({...p,lastReport:this.data.reports.filter(r=>r.projectId===p.id).at(-1)||null}));}
  project(id){const p=this.data.projects.find(p=>p.id===id);if(!p)throw new Error('Το έργο δεν βρέθηκε.');return p;}
  saveProject(input){
    const prior=input.id?this.project(input.id):null;const u=new URL(String(input.url));
    if(!['http:','https:'].includes(u.protocol)||u.username||u.password||u.search)throw new Error('Χρησιμοποίησε HTTP(S) URL χωρίς κωδικούς ή query parameters.');
    u.hash='';const schedule=['off','daily','weekly'].includes(input.schedule)?input.schedule:'off';
    if(!input.authorized)throw new Error('Επιβεβαίωσε ότι έχεις άδεια για το site και το συνδεδεμένο repository.');
    const p={id:prior?.id||randomUUID(),name:String(input.name||u.hostname).slice(0,120),client:String(input.client||'').slice(0,120),url:u.href,repository:String(input.repository||'').trim(),authorized:true,browser:input.browser!==false,useAI:Boolean(input.useAI),maxPages:Math.min(20,Math.max(1,Number(input.maxPages)||10)),schedule,nextRun:prior?.schedule===schedule?prior.nextRun:(schedule==='off'?null:new Date(Date.now()+interval(schedule)).toISOString()),createdAt:prior?.createdAt||new Date().toISOString()};
    p.cveWatch=Boolean(input.cveWatch??prior?.cveWatch);p.wordpress=Boolean(input.wordpress??prior?.wordpress);if(prior)Object.assign(prior,p);else this.data.projects.push(p);this.commit();return p;
  }
  chat(projectId){this.project(projectId);return (this.data.chats||{})[projectId]||[];}
  addChat(projectId,role,text,extra={}){this.project(projectId);this.data.chats||={};const entries=this.data.chats[projectId]||=[];const message={id:randomUUID(),role,text:String(text).slice(0,16000),createdAt:new Date().toISOString(),...extra};entries.push(message);this.data.chats[projectId]=entries.slice(-100);this.commit();return message;}
  saveResearch(projectId,value){this.project(projectId);this.data.research||={};this.data.research[projectId]=value;this.commit();}
  research(projectId){return this.data.research?.[projectId]||null;}
  history(projectId){return this.data.reports.filter(r=>!projectId||r.projectId===projectId).slice().reverse();}
  report(id){if(!/^[a-f0-9-]{36}$/.test(id))throw new Error('Invalid report ID');return JSON.parse(fs.readFileSync(path.join(this.dir,'reports',id+'.json'),'utf8'));}
  saveReport(projectId,report){const prior=this.data.reports.filter(r=>r.projectId===projectId).at(-1);report.id=randomUUID();report.projectId=projectId;report.completedAt=new Date().toISOString();
    const baseline=prior?this.report(prior.id):null;
    // Carry forward unresolved older findings so partial scans cannot erase them.
    if(baseline)baseline.findings=[...baseline.findings,...(baseline.resolved||[]).filter(f=>f.status==='needs_verification')];
    if(baseline?.authContext!==report.authContext)report.coverage=[];
    compareReports(baseline,report);report.evidenceDiff=require('./advanced').evidenceDiff(baseline,report);require('./advanced').annotate(report);atomic(path.join(this.dir,'reports',report.id+'.json'),report);
    this.data.reports.push({id:report.id,projectId,target:report.target,completedAt:report.completedAt,status:report.status,summary:report.summary,comparison:report.comparison});this.commit();return report;
  }
  setStatus(reportId,findingId,status){if(!['open','needs_verification'].includes(status))throw new Error('Η επίλυση επιβεβαιώνεται μόνο με επανέλεγχο.');const r=this.report(reportId);const f=[...r.findings,...(r.resolved||[])].find(f=>f.id===findingId);if(!f)throw new Error('Το εύρημα δεν βρέθηκε.');f.status=status;atomic(path.join(this.dir,'reports',r.id+'.json'),r);return r;}
  due(now=Date.now()){return this.data.projects.filter(p=>p.authorized&&p.schedule!=='off'&&p.nextRun&&Date.parse(p.nextRun)<=now);}
  advance(id,now=Date.now()){const p=this.project(id);p.nextRun=p.schedule==='off'?null:new Date(now+interval(p.schedule)).toISOString();this.commit();}
}
function interval(schedule){return (schedule==='weekly'?7:1)*86400000;}
module.exports={Store,atomic,interval};
