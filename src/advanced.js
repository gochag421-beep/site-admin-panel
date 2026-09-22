const {safeText}=require('./privacy');
function dependencies(file,text){
  if(file.endsWith('composer.lock')){const d=JSON.parse(text);return [...(d.packages||[]),...(d['packages-dev']||[])].filter(p=>/^v?\d+\.\d+/.test(p.version)).map(p=>({name:p.name,version:p.version.replace(/^v/,''),ecosystem:'Packagist'}));}
  if(file.endsWith('requirements.txt'))return text.split(/\r?\n/).map(line=>line.match(/^\s*([\w.-]+)(?:\[[^\]]+\])?==([\w.+-]+)\s*(?:#.*)?$/)).filter(Boolean).map(m=>({name:m[1].toLowerCase().replace(/[-_.]+/g,'-'),version:m[2],ecosystem:'PyPI'}));
  return [];
}
function wordpressInventory($,page){
  const rows=[];const gen=$('meta[name="generator"]').attr('content')||'';const core=gen.match(/WordPress\s+(\d+(?:\.\d+){1,3})/i);
  if(core)rows.push({type:'core',slug:'wordpress',version:core[1],source:page,confidence:'banner-unverified'});
  $('[src],[href]').each((_,el)=>{const raw=$(el).attr('src')||$(el).attr('href');try{const u=new URL(raw,page);if(u.origin!==new URL(page).origin)return;const m=u.pathname.match(/\/wp-content\/(plugins|themes)\/([a-z0-9_-]+)\//i);if(m)rows.push({type:m[1]==='plugins'?'plugin':'theme',slug:m[2],version:/^\d+(?:\.\d+){1,3}$/.test(u.searchParams.get('ver')||'')?u.searchParams.get('ver'):null,source:page,confidence:'asset-unverified'});}catch{}});
  return [...new Map(rows.map(r=>[r.type+':'+r.slug,r])).values()].slice(0,30);
}
function annotate(report){for(const f of report.findings){f.confidence=f.vulnerability?'version-match':f.kind==='observed'?'observed':f.kind==='needs_confirmation'?'unconfirmed':'configuration';f.confirmation=f.vulnerability?'Επηρεαζόμενη έκδοση στο repository. Η ανάπτυξη στην παραγωγή χρειάζεται επιβεβαίωση.':f.kind==='needs_confirmation'?'Χρειάζεται χειροκίνητη επιβεβαίωση.':'Καταγραφή συγκεκριμένου ελέγχου· δεν αποδεικνύει εκμετάλλευση.';if(f.verification)f.confirmation+=' Επαναληπτικός έλεγχος: '+({repeated:'παρατηρήθηκε ξανά',inconsistent:'διαφορετικό αποτέλεσμα',unavailable:'μη διαθέσιμος'}[f.verification.result]||'άγνωστο')+'.';}return report;}
function evidenceDiff(before,after){const old=new Map((before?.findings||[]).map(f=>[f.id,f]));const current=new Map(after.findings.map(f=>[f.id,f]));return [...new Set([...old.keys(),...current.keys()])].map(id=>{const a=old.get(id),b=current.get(id);return {id,title:(b||a).title,before:a?.evidence||null,after:b?.evidence||null,state:!a?'new':!b?(after.resolved||[]).find(f=>f.id===id)?.status||'needs_verification':a.evidence===b.evidence?'persistent':'changed'};});}
function remediationBundle(report){
 const ids=new Set(report.findings.map(f=>f.checkId));const nginx=[];const apache=[];
 const rules=[['nosniff','X-Content-Type-Options','nosniff'],['referrer','Referrer-Policy','strict-origin-when-cross-origin']];
 for(const [id,name,value] of rules)if(ids.has(id)){nginx.push(`add_header ${name} "${value}" always;`);apache.push(`Header always set ${name} "${value}"`);}
 return {version:1,target:report.target,reportId:report.id,generatedAt:new Date().toISOString(),instructions:'Πρόταση για έλεγχο σε staging. Έλεγξε το server config και τη συμβατότητα πριν εφαρμογή. Δεν εφαρμόστηκε αλλαγή.',files:[{name:'nginx-security.conf',content:nginx.join('\n')},{name:'apache-security.conf',content:apache.join('\n')}].filter(f=>f.content),review:report.findings.map(f=>({title:f.title,action:safeText(f.recommendation)}))};
}
function remediationPatch(report){const proposal=remediationBundle(report);if(!proposal.files.length)throw new Error('Δεν υπάρχει αυτοματοποιημένο patch για τα συγκεκριμένα ευρήματα. Δες τις οδηγίες της αναφοράς.');return proposal.files.map(f=>{const lines=['# Vexon proposal: review in staging before deployment.','# Include this snippet in the correct server context.',...f.content.split('\n')];const name='vexon-proposals/'+f.name;return `diff --git a/${name} b/${name}\nnew file mode 100644\n--- /dev/null\n+++ b/${name}\n@@ -0,0 +1,${lines.length} @@\n`+lines.map(l=>'+'+l).join('\n')+'\n';}).join('');}
module.exports={dependencies,wordpressInventory,annotate,evidenceDiff,remediationBundle,remediationPatch};
