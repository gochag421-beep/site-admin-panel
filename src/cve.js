const {safeText}=require('./privacy');
let nextNvd=0;
async function api(url,{signal,fetchImpl=fetch}={}){
 const r=await fetchImpl(url,{redirect:'error',signal:signal?AbortSignal.any([signal,AbortSignal.timeout(20000)]):AbortSignal.timeout(20000),headers:{Accept:'application/json'}});
 if(!r.ok)throw new Error(`Η πηγή επέστρεψε HTTP ${r.status}. Δεν προέκυψε συμπέρασμα ασφάλειας.`);
 return r.json();
}
function osvDetails(record,packageName){
 const affected=(record.affected||[]).filter(a=>a.package?.name===packageName);
 return {id:record.id,cves:(record.aliases||[]).filter(x=>/^CVE-\d{4}-\d+$/i.test(x)),description:safeText(record.summary||record.details||'Δεν παρέχεται περιγραφή.'),
 severity:record.database_specific?.severity||'Δεν παρέχεται',cvss:(record.severity||[]).map(s=>`${s.type}: ${s.score}`),
 fixes:[...new Set(affected.flatMap(a=>(a.ranges||[]).flatMap(r=>(r.events||[]).filter(e=>e.fixed).map(e=>e.fixed))))],
 references:(record.references||[]).map(r=>r.url).filter(u=>/^https:\/\//i.test(u)).slice(0,8),source:`https://osv.dev/vulnerability/${encodeURIComponent(record.id)}`,withdrawn:Boolean(record.withdrawn),retrievedAt:new Date().toISOString()};
}
async function enrichCVEs(report,options={}){
 const findings=report.findings.filter(f=>f.checkId.startsWith('osv:'));const cache=new Map();
 for(const f of findings){if(options.signal?.aborted)break;const id=decodeURIComponent(new URL(f.url).pathname.split('/').at(-1));
   if(cache.size>=40&&!cache.has(id)){report.errors.push({module:'cve',error:'Εμπλουτισμός περιορίστηκε σε 40 αναφορές OSV.'});break;}
   try{if(!cache.has(id))cache.set(id,await api(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`,options));
    const info=osvDetails(cache.get(id),f.checkId.slice(4));f.vulnerability={...info,match:'package-version',evidence:f.evidence};
    f.title=`${info.cves.join(', ')||id} · ${f.checkId.slice(4)}`;
    if(['CRITICAL','HIGH','MODERATE','MEDIUM','LOW'].includes(info.severity.toUpperCase()))f.severity=info.severity.toUpperCase()==='MODERATE'?'medium':info.severity.toLowerCase();
    f.evidence+=` ${info.description}`;
    f.recommendation=info.withdrawn?'Η αναφορά έχει αποσυρθεί: χρειάζεται νέα επιβεβαίωση.':info.fixes.length?`Εκδόσεις διόρθωσης που αναφέρονται για το πακέτο: ${info.fixes.join(', ')}. Έλεγξε τη σωστή γραμμή εκδόσεων και συμβατότητα στην πηγή.`:'Δεν παρέχεται συγκεκριμένη έκδοση διόρθωσης. Συμβουλεύσου την επίσημη αναφορά.';
    if(info.withdrawn){f.kind='needs_confirmation';f.severity='info';}
   }catch(e){report.errors.push({module:'cve',error:`${id}: ${safeText(e.message)}`});}
 }
 report.cve={checkedAt:new Date().toISOString(),matched:findings.filter(f=>f.vulnerability).length,source:'OSV',note:'Αντιστοίχιση ακριβούς έκδοσης εξάρτησης, όχι απόδειξη εκμεταλλευσιμότητας.'};
}
function nvdRecords(data){return (data.vulnerabilities||[]).map(({cve})=>{const metrics=cve.metrics||{};const metric=(metrics.cvssMetricV40||metrics.cvssMetricV31||metrics.cvssMetricV30||metrics.cvssMetricV2||[])[0];return {id:cve.id,description:safeText(cve.descriptions?.find(d=>d.lang==='en')?.value||''),score:metric?.cvssData?.baseScore??null,vector:metric?.cvssData?.vectorString||'',severity:metric?.cvssData?.baseSeverity||metric?.baseSeverity||'Unknown',status:cve.vulnStatus,source:`https://nvd.nist.gov/vuln/detail/${cve.id}`,references:(cve.references||[]).map(r=>r.url).filter(u=>/^https:\/\//.test(u)).slice(0,5),match:'candidate',note:'Αποτέλεσμα αναζήτησης. Δεν επιβεβαιώθηκε η εφαρμογή του στην ιστοσελίδα.'};});}
async function searchCVEs(query,{signal,fetchImpl=fetch,sleep=ms=>new Promise(r=>setTimeout(r,ms))}={}){
 query=String(query||'').trim().slice(0,160);if(!query)throw new Error('Δώσε προϊόν ή CVE ID, π.χ. «ψάξε CVE για WordPress».');
 const url=new URL('https://services.nvd.nist.gov/rest/json/cves/2.0');url.searchParams.set('resultsPerPage','10');
 if(/^CVE-\d{4}-\d{4,}$/i.test(query))url.searchParams.set('cveId',query.toUpperCase());else url.searchParams.set('keywordSearch',query);
 const wait=Math.max(0,nextNvd-Date.now());nextNvd=Date.now()+wait+6500;if(wait)await sleep(wait);
 if(signal?.aborted)throw new Error('Ακυρώθηκε.');
 const data=await api(url.href,{signal,fetchImpl});return {query,source:'NVD',sourceUrl:url.href,retrievedAt:new Date().toISOString(),total:data.totalResults??0,items:nvdRecords(data),note:'Προβάλλονται έως 10 αποτελέσματα. Τα αποτελέσματα αναζήτησης δεν είναι επιβεβαιωμένα ευρήματα ιστοσελίδας.'};
}
module.exports={osvDetails,enrichCVEs,nvdRecords,searchCVEs};
