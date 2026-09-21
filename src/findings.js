const {hash,safeText,safeUrl}=require('./privacy');
const weights={critical:12,high:8,medium:4,low:1,info:0};
function finding(checkId,{severity='low',title,evidence,recommendation,url,subject='',kind='recommendation',module='http',scope}) {
  url=safeUrl(url);scope=scope||`${module}:${url}`;
  return {id:hash([checkId,url,subject].join('|')),checkId,scope,module,severity,title,kind,evidence:safeText(evidence),recommendation:safeText(recommendation),url,status:'open'};
}
function summarize(report) {
  report.findings=[...new Map(report.findings.map(f=>[f.id,f])).values()].sort((a,b)=>weights[b.severity]-weights[a.severity]);
  const counts={critical:0,high:0,medium:0,low:0,info:0};report.findings.forEach(f=>counts[f.severity]++);
  const success=report.pagesScanned?.length>0;
  report.status=report.cancelled?'cancelled':!success?'failed':report.errors.length?'partial':'complete';
  const penalties=new Map();for(const f of report.findings)penalties.set(f.checkId,Math.max(penalties.get(f.checkId)||0,weights[f.severity]));
  // No healthy score for an incomplete scan. This is a configuration score, not a security guarantee.
  report.summary={score:report.status==='complete'?Math.max(0,100-[...penalties.values()].reduce((a,b)=>a+b,0)):null,counts,total:report.findings.length};
  return report;
}
function compareReports(previous,current) {
  const old=new Map((previous?.findings||[]).map(f=>[f.id,f]));const now=new Set(current.findings.map(f=>f.id));
  current.findings=current.findings.map(f=>({...f,status:'open',change:old.has(f.id)?'persistent':'new'}));
  current.resolved=[];
  for(const f of old.values()) if(!now.has(f.id)) current.resolved.push({...f,status:(current.coverage||[]).includes(`${f.scope}|${f.checkId}`)?'resolved':'needs_verification',change:'absent'});
  current.comparison={baselineId:previous?.id||null,new:current.findings.filter(f=>f.change==='new').length,resolved:current.resolved.filter(f=>f.status==='resolved').length,unverified:current.resolved.filter(f=>f.status==='needs_verification').length};
  return current;
}
module.exports={finding,summarize,compareReports};
