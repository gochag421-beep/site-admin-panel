const {finding}=require('./findings');const {safeText}=require('./privacy');
function parseRepo(value){const text=value.replace(/^https:\/\/github\.com\//,'').replace(/\.git$/,'').replace(/\/$/,'');if(!/^[\w.-]+\/[\w.-]+$/.test(text))throw new Error('Repository: owner/name ή https://github.com/owner/name');return text;}
async function jsonFetch(url,options={},signal,fetchImpl=fetch){const timeout=AbortSignal.timeout(20000);const r=await fetchImpl(url,{...options,signal:signal?AbortSignal.any([signal,timeout]):timeout,redirect:'error'});if(!r.ok)throw new Error(`API HTTP ${r.status}`);return r.json();}
const rules=[
  ['secret-key','Πιθανό εκτεθειμένο API key','high',/\b(?:sk-(?:or-v1-)?[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[A-Z0-9]{16})\b/,'Επαλήθευσε το εύρημα. Αν είναι πραγματικό secret, ανάκληση/αντικατάσταση και αφαίρεση από το ιστορικό Git.'],
  ['private-key','Ιδιωτικό κλειδί στον κώδικα','high',/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,'Μετέφερε το κλειδί σε ασφαλή αποθήκευση και αντικατάστησέ το αν εκτέθηκε.'],
  ['tls-disabled','Απενεργοποιημένη επαλήθευση TLS','medium',/(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0)/,'Επαλήθευσε τη χρήση. Οι συνδέσεις παραγωγής πρέπει να ελέγχουν το πιστοποιητικό.'],
  ['debug-enabled','Ρύθμιση debug στον κώδικα','low',/(?:DEBUG\s*=\s*(?:True|true)|app\.run\([^\n]*debug\s*=\s*True)/,'Απενεργοποίησε το debug στην παραγωγή.'],
  ['unsafe-eval','Χρήση eval που χρειάζεται εξέταση','medium',/\beval\s*\(/,'Έλεγξε αν εισέρχονται μη έμπιστα δεδομένα. Η ύπαρξη eval δεν αποδεικνύει εκμεταλλεύσιμη ευπάθεια.']
];
function inspectSource(text,file,url,report){const scope=`source:${url}`;for(const [id,title,severity,pattern,rec] of rules){report.coverage.push(`${scope}|${id}`);const lines=text.split(/\r?\n/);const hits=[];for(let i=0;i<lines.length;i++)if(pattern.test(lines[i]))hits.push(i+1);
  if(hits.length)report.findings.push(finding(id,{module:'source',scope,url,severity,title,kind:'needs_confirmation',subject:file,evidence:`${file}; γραμμές ${hits.slice(0,15).join(', ')}. Περιεχόμενο/τιμές δεν αποθηκεύονται.`,recommendation:rec}));}}
function packagesFromLock(lock){const out=[];if(lock.packages){for(const [key,p] of Object.entries(lock.packages))if(key&&p.version&&key.includes('node_modules/'))out.push({name:p.name||key.split('node_modules/').at(-1),version:p.version});}
  else{const visit=deps=>{for(const [name,p] of Object.entries(deps||{})){if(p.version)out.push({name,version:p.version});visit(p.dependencies);}};visit(lock.dependencies);}
  return [...new Map(out.filter(p=>/^\d+\.\d+\.\d+/.test(p.version)).map(p=>[p.name+'@'+p.version,p])).values()];}
async function scanSource(repository,report,{token,signal,progress=()=>{},fetchImpl=fetch}={}){
  report.modules.source='running';report.source={repository,filesChecked:0,packagesChecked:0,limitations:[]};
  try{
    const repo=parseRepo(repository);const headers={'Accept':'application/vnd.github+json','User-Agent':'Vexon-Security-Scanner',...(token?{Authorization:`Bearer ${token}`}:{})};
    const get=path=>jsonFetch(`https://api.github.com/repos/${repo}/${path}`,{headers},signal,fetchImpl);
    const meta=await get('');const commit=await get(`commits/${encodeURIComponent(meta.default_branch)}`);const ref=commit.sha;report.source.commit=ref;
    const tree=await get(`git/trees/${ref}?recursive=1`);
    if(tree.truncated)report.source.limitations.push('Το GitHub επέστρεψε περικομμένο tree.');
    const eligible=tree.tree.filter(f=>f.type==='blob'&&!/(^|\/)(node_modules|vendor|dist|build|\.git)\//.test(f.path)&&(/\.(js|jsx|ts|tsx|py|php|json|ya?ml|env|pem|key|conf)$/i.test(f.path)||/\/?.env(?:\.|$)/.test(f.path)));
    const priority=f=>f.path.endsWith('package-lock.json')?0:/env|pem|key|config/i.test(f.path)?1:2;
    eligible.sort((a,b)=>priority(a)-priority(b)||a.path.localeCompare(b.path));
    const candidates=eligible.filter(f=>f.size<=2_000_000).slice(0,60);
    if(candidates.length<eligible.length)report.source.limitations.push(`Ελέγχθηκαν έως 60 αρχεία ≤2 MB από ${eligible.length} υποψήφια.`);
    let dependencies=[];
    for(const file of candidates){if(signal?.aborted)throw new Error('Cancelled');progress({stage:'source',percent:70,message:`GitHub: ${report.source.filesChecked+1}/${candidates.length} αρχεία`});
      const blob=await get(`git/blobs/${file.sha}`);if(blob.encoding!=='base64')continue;
      const text=Buffer.from(blob.content,'base64').toString('utf8');const url=`https://github.com/${repo}/blob/${meta.default_branch}/${file.path}`;
      inspectSource(text,file.path,url,report);report.source.filesChecked++;
      if(file.path.endsWith('package-lock.json')){try{dependencies.push(...packagesFromLock(JSON.parse(text)));}catch{report.source.limitations.push('Μη έγκυρο package-lock.json.');}}
    }
    dependencies=[...new Map(dependencies.map(p=>[p.name+'@'+p.version,p])).values()];
    if(dependencies.length>300)report.source.limitations.push('Έλεγχος OSV περιορίστηκε στα πρώτα 300 πακέτα.');
    if(!dependencies.length)report.source.limitations.push('Δεν βρέθηκαν ακριβείς npm εκδόσεις σε package-lock.json. Άλλα οικοσυστήματα δεν καλύπτονται.');
    const packages=dependencies.slice(0,300);const scope=`dependencies:${repo}`;
    for(let start=0;start<packages.length;start+=50){const chunk=packages.slice(start,start+50);
      const results=await jsonFetch('https://api.osv.dev/v1/querybatch',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({queries:chunk.map(p=>({package:{name:p.name,ecosystem:'npm'},version:p.version}))})},signal,fetchImpl);
      if(!Array.isArray(results.results)||results.results.length!==chunk.length)throw new Error('Incomplete OSV response');
      results.results.forEach((r,i)=>{const p=chunk[i];const checkId=`osv:${p.name}`;
        if(r.next_page_token)report.source.limitations.push(`Περικοπή OSV για ${p.name}.`);else report.coverage.push(`${scope}|${checkId}`);
        for(const v of r.vulns||[])report.findings.push(finding(checkId,{module:'source',scope,url:`https://osv.dev/vulnerability/${encodeURIComponent(v.id)}`,subject:repo,severity:'medium',kind:'observed',title:`Γνωστή αναφορά OSV: ${p.name}`,evidence:`${p.name}@${p.version}; ${v.id}. Η αντιστοίχιση έκδοσης δεν αποδεικνύει εκμεταλλευσιμότητα.`,recommendation:'Δες την αναφορά OSV και αναβάθμισε σε έκδοση που διορθώνει την ευπάθεια.'}));
      });report.source.packagesChecked+=chunk.length;
    }
    report.modules.source=report.source.limitations.length?'partial':'complete';
    for(const note of report.source.limitations)report.errors.push({module:'source',error:note});
  }catch(e){report.modules.source='partial';report.errors.push({module:'source',error:safeText(e.message)});}
}
module.exports={parseRepo,inspectSource,packagesFromLock,scanSource};
