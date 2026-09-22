const {inspectPage}=require('./scanner');const {getPage}=require('./network');
async function verifyObservations(report,{request=getPage,signal,progress=()=>{}}={}){
 for(const url of [...new Set(report.findings.filter(f=>f.module==='http').map(f=>f.url))].slice(0,3)){
  if(signal?.aborted)break;const items=report.findings.filter(f=>f.module==='http'&&f.url===url);progress({stage:'verify',percent:67,message:'Επαναληπτικός έλεγχος: '+new URL(url).pathname});
  try{const response=await request(url,{signal});if(response.status<200||response.status>=300)throw new Error('HTTP '+response.status);const sample={findings:[],coverage:[]};inspectPage(url,response,sample);const seen=new Set(sample.findings.map(f=>f.id));for(const f of items){if(!sample.coverage.includes(f.scope+'|'+f.checkId))continue;f.verification={checkedAt:new Date().toISOString(),result:seen.has(f.id)?'repeated':'inconsistent'};if(!seen.has(f.id)){f.kind='needs_confirmation';report.coverage=report.coverage.filter(c=>c!==f.scope+'|'+f.checkId);}}}catch{for(const f of items)f.verification={result:'unavailable'};report.errors.push({module:'verification',error:'Ο επαναληπτικός έλεγχος δεν ολοκληρώθηκε.',url});}
 }
}
module.exports={verifyObservations};
